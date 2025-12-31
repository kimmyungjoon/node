const express = require('express');
const sql = require('mssql');
const jwt = require('jsonwebtoken');
const app = express();
const port = 3000;

app.use(express.json());
app.use(express.urlencoded({extended: true}));

// 토큰 암호화용 비밀키
const SECRET_KEY = 'photomon';

// MSSQL 연결설정
const dbConfig = {
    user: 'start6254',
    password: 'silverred78_',
    server: 'localhost',
    database: 'node',
    options: {
        encrypt: false,
        trustServerCertificate: true
    }
};

// 토큰 검증 미들웨어(로그인이 필요한 서비스에 사용)
const verifyToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // "Bearer TOKEN" 형태

    if (!token) return res.status(403).json({
        resultcode: "9403",
        resultmsg: "토큰이 없습니다."
    });

    jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if (err) return res.status(401).json({
            resultcode: "9401",
            resultmsg: "유효하지 않은 토큰입니다."
        });
        req.user = decoded; // 다음 단계에서 사용자 정보를 쓸 수 있게 담아둠
        next();
    });
}

// 메인
app.get('/', async (req, res) => {
    res.json({
        resultcode: "0000",
        resultmsg: "성공"
    });
});
// 로그인
app.get('/login', async (req, res) => {
    const {id, pwd} = req.body;
    
    try {
            let pool = await sql.connect(dbConfig);
            let result = await pool.request()
            .input('id', sql.NVarChar, id)
            .input('pwd', sql.NVarChar, pwd)
            .query('SELECT * FROM member WHERE id=@id AND pwd=@pwd');

            if (result.recordset.length > 0) {
                const user = result.recordset[0];
                const payload = {idx: user.idx, id: user.id, name: user.name};

                // Access Token 발급 (15분)
                const accessToken = jwt.sign(payload, SECRET_KEY, {expiresIn: '15m'});

                // Refresh Token 발급 (14일)
                const refreshToken = jwt.sign(payload, SECRET_KEY, {expiresIn: '14d'});

                // DB에 Refresh Token 저장
                await pool.request()
                .input('refreshtoken', sql.NVarChar, refreshToken)
                .input('id', sql.NVarChar, user.id)
                .query('UPDATE member SET refresh_token = @refreshtoken WHERE id = @id');

                // 클라이언트에게 토큰 전달
                res.json({
                    resultcode: "0000",
                    resultmsg: "로그인 성공",
                    accessToken: accessToken,
                    refreshToken: refreshToken
                });
            } else {
                res.status(401).json({
                    resultcode: "9401",
                    resultmsg: "아이디 또는 비번이 틀립니다."
                });
            }
    } catch (err) {
                res.status(500).json({
                    resultcode: "9500",
                    resultmsg: "로그인 처리 중 오류 발생"
                });
    }
});
// 토큰 갱신: Refresh Token을 사용하여 새로운 Access Token 발급
app.get('/refresh', async (req, res) => {
    const {refreshToken} = req.body;
    if (!refreshToken) {
        return res.status(403).json({
            resultcode: "9403",
            resultmsg: "리프레시 토큰이 없습니다."
        });
    }

    try {
        let pool = await sql.connect(dbConfig);

        // DB에 해당 Refresh Token이 있는지 확인
        let result = await pool.request()
        .input('refreshToken', sql.NVarChar, refreshToken)
        .query('SELECT id, name, idx FROM member WHERE refresh_token = @refreshToken');

        if (result.recordset.length === 0) {
            return res.status(403).json({
                resultcode: "9403",
                resultmsg: "유효하지 않은 리프레시 토큰입니다."
            })
        }

        // 토큰 유효성 및 만료 기간 검증
        jwt.verify(refreshToken, SECRET_KEY, (err, decoded) => {
            if (err) {
                return res.status(403).json({
                    resultcode: "9403",
                    resultmsg: "리프레시 토큰이 만료되었습니다. 다시 로그인하세요."
                });

                // 검증 성공 시 새로운 Access Token 발급
                const newAccessToken = jwt.sign(
                    {idx: decoded.idx, id: decoded.id, name: decoded.nam},
                    SECRET_KEY,
                    {expiresIn: '1h'}
                );

                res.json({
                    resultcode: "0000",
                    resultmsg: "토큰 갱신 성공",
                    accessToken: newAccessToken
                });
            }
        });
    } catch (err) {
        res.status(500).json({
            resultcode: "9500",
            resultmsg: "토큰 갱신 중 오류 발생"
        })
    }
});
// 회원페이지
app.get('/member', verifyToken, (req, res) => {
    res.json({
        resultcode: "0000",
        resultmsg: "성공",
        user: req.user // 미들웨어에서 담아준 사용자 정보
    });
});

// 로그아웃 (DB의 Refresh Token 삭제)
app.post('/logout', verifyToken, async (req, res) => {
    try {
            let pool = await sql.connect(dbConfig);
            await pool.request()
            .inmput('id', sql.NVarChar, req.user.id)
            .query('UPDATE member SET refresh_token = NULL WHERE id = @id');

            res.json({
                resultcode: "0000",
                resultmsg: "로그아웃 성공"
            });
    } catch (err) {
            res.status(500).json({
                resultcode: "9500",
                resultmsg: "로그아웃 처리 중 오류 발생"
            });
    }
});

app.listen(port, () => {
    console.log(`서버가 포트 ${port}에서 실행 중입니다.`);
});