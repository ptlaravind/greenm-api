const jwt = require('jsonwebtoken');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');
const crypto = require("crypto");
const { SecretManagerServiceClient } = require("@google-cloud/secret-manager");

const client = new SecretManagerServiceClient();

const algorithm = "aes-256-cbc";

async function getSecret() {
    const projectId = process.env.projectId;
    const secretName = "greenm-secret";

    const [version] = await client.accessSecretVersion({
        name: `projects/${projectId}/secrets/${secretName}/versions/latest`,
    });

    const secretValue = version.payload.data.toString("utf8");

    console.log(secretValue);
    return JSON.parse(secretValue);
}

exports.handler = async (req, res) => {
    try {
        console.log("Entered....");

        const authHeader = req.headers['authorization'];
        const secret = await getSecret();
        const secretUserName = secret.username;
        const secretPassword = decrypt(secret.password, secret.encryptKey, secret.encryptIV);
        const username = req.headers['username'];
        const password = req.headers['password'];

        if (
            username !== secretUserName ||
            password !== secretPassword
        ) {
            return res.status(401).json({
                message: "Invalid username or password"
            });
        }

        console.log("Basic Authentication successful.");
        const tokenEndpoint = process.env.tokenEndpoint;

        const privateKey = fs.readFileSync('./certs/private.key', 'utf8');
        const now = Math.floor(Date.now() / 1000);

        const payload = {
            jti: uuidv4(),
            iat: now,
            exp: now + 300
        };

        const token = jwt.sign(payload, privateKey, {
            algorithm: "RS256"
        });

        console.log("JWT generated successfully.");
        console.log("tokenEndpoint " + tokenEndpoint);

        const response = await fetch(tokenEndpoint, {
            method: "POST",
            headers: {
                "Authorization": `Bearer ${token}`,
                "Content-Type": "application/json"
            }
        });

        console.log("response status: " + response.status);
        const validateResult = await response.json();

        return res.status(response.status).json(validateResult);

    } catch (error) {
        console.error(error);
        return res.status(500).json({
            error: error.message
        });
    }
};

function encrypt(text, key, iv) {
    const cipher = crypto.createCipheriv(algorithm, Buffer.from(key, "hex"), Buffer.from(iv, "hex"));
    let encrypted = cipher.update(text, "utf8", "hex");
    encrypted += cipher.final("hex");
    return encrypted;
}

function decrypt(encryptedText, key, iv) {
    const decipher = crypto.createDecipheriv(algorithm, Buffer.from(key, "hex"), Buffer.from(iv, "hex"));
    let decrypted = decipher.update(encryptedText, "hex", "utf8");
    decrypted += decipher.final("utf8");
    return decrypted;
}