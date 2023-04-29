import express, { Express, Request, Response } from 'express';
import dotenv from 'dotenv';
import { PrismaClient } from '@prisma/client'
import jwt from 'jsonwebtoken'

const prisma = new PrismaClient()

dotenv.config();

const app: Express = express();
const port = 8080;

app.use(express.json());

const jwtSecret = process.env.JWT_SECRET || 'blnbmb';

interface UserModel {username:string, password:string, email:string}
interface UserLoginModel {username:string, password:string}
interface JwtModel {username:string, token:string}

// Registration endpoint
app.post('/api/auth/register', async (req: Request<null, UserModel>, res: Response) => {

   const newUser = await prisma.user.create({data:{username:req.body.username, password:req.body.password, email:req.body.email, role:"consumer"}})
   return res.json({
    success: true,
    data: newUser
    });
}
)

// Login endpoint
app.post('/api/auth/login', async (req: Request<null, UserLoginModel>, res: Response) => {
    try {
        //TODO: Add password hashing to registrations and logins

        // Get user from database
        const user = await prisma.user.findFirst({
            where: {
                username: req.body.username,
                password: req.body.password
            },
        });
        
        if (!user) {
            return res.json({
                success: false,
                message: 'Invalid credentials',
            });
        }

        // Create JWT token
        const token = jwt.sign({ userId: user.id }, jwtSecret, { expiresIn: '1h' });

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
app.post('/api/validation', async (req: Request<null, JwtModel>, res: Response) => {
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
  console.log(`⚡️[server]: Server is running at http://localhost:${port}`);
});

