import express, { Express, Request, Response } from 'express';
import dotenv from 'dotenv';

process.env.DATABASE_URL = fs.readFileSync('/run/secrets/DATABASE_URL', 'utf8').trim();
import { PrismaClient } from '@prisma/client'
import jwt from 'jsonwebtoken'
import fs from 'fs'
const prisma = new PrismaClient()

dotenv.config();

const app: Express = express();
const port = 80;

app.use(express.json());

// Read JWT secret from docker secret file
const jwtSecret = fs.readFileSync('/run/secrets/JWT_SECRET', 'utf8').trim();

interface UserModel { username: string, password: string, email: string }
interface UserLoginModel { username: string, password: string }
interface JwtModel { username: string, token: string }

// Registration endpoint
app.post('/api/auth/register', async (req: Request<null, UserModel>, res: Response) => {
    const bcrypt = require('bcrypt');
    const saltRounds = 10;
    const plaintextPassword = req.body.password;

    try {
        const salt = bcrypt.genSaltSync(saltRounds);
        const hash = bcrypt.hashSync(plaintextPassword, salt);
        const newUser = await prisma.user.create({ data: { username: req.body.username, password: hash, email: req.body.email, role: "consumer" } })
        return res.json({
            success: true,
            data: newUser
        });
    } catch (error) {
        console.log(error)
        return res.json({
            success: false,
            message: error
        });
    }

}
)

// Login endpoint
app.post('/api/auth/login', async (req: Request<null, UserLoginModel>, res: Response) => {
    try {
        const bcrypt = require('bcrypt');

        // Get user from database
        const user = await prisma.user.findFirst({
            where: {
                username: req.body.username,
            },
        });

        if (!user || !bcrypt.compareSync(req.body.password, user.password)) {
            return res.json({
                success: false,
                message: 'Invalid credentials',
            });
        }

        // Create JWT token
        const token = jwt.sign({ userId: user.id, role: user.role }, jwtSecret, { expiresIn: '1h' });

        return res.json({
            success: true,
            data: {
                token,
            },
        });
    } catch (error) {
        return res.json({
            success: false,
            message: error
        });
    }
});


// Validation endpoint
app.post('/api/auth/validation', async (req: Request<null, JwtModel>, res: Response) => {
    try {
        jwt.verify(req.body.token, jwtSecret)

        return res.json({
            success: true,
        });
    } catch (error) {
        return res.json({
            success: false,
            message: error
        });
    }
});

app.listen(port, () => {
    console.log("SECRET" + jwtSecret)
    console.log(`⚡️[server]: Server is running at port port`);
});

