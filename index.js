const jwt = require('jsonwebtoken');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');
 
// GCP HTTP functions use (req, res) signature
exports.handler = async (req, res) => {
    try {
        console.log("Entered....");
       
        // ===============================
        // Validate Basic Authentication
        // ===============================
        // Express normalizes headers to lowercase automatically
        const authHeader = req.headers['authorization'];
        console.log("authHeader " + authHeader);
       
        // if (!authHeader || !authHeader.startsWith("Basic ")) {
        //     return res.status(401).json({
        //         message: "Missing Basic Authorization header"
        //     });
        // }
 
        // const encodedCredentials = authHeader.split(" ")[1];
        // const [username, password] = Buffer.from(encodedCredentials, "base64")
        //     .toString("utf8")
        //     .split(":");
        const username = req.headers['username'];
        const password = req.headers['password'];
           
        console.log("username " + username);
        console.log("password " + password);
       
        if (
            username !== process.env.username ||
            password !== process.env.password
        ) {
            return res.status(401).json({
                message: "Invalid username or password"
            });
        }
 
        console.log("Basic Authentication successful.");
 
        // ===============================
        // Create JWT
        // ===============================
        const tokenEndpoint = process.env.tokenEndpoint;
 
        // Note: Ensure the './certs/private.key' folder is included inside your zip file
        const privateKey = fs.readFileSync('./certs/private.key', 'utf8');
        console.log("privateKey " + privateKey);
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
       
        // ===============================
        // Call Validation API
        // ===============================
        const response = await fetch(tokenEndpoint, {
            method: "POST",
            headers: {
                "Authorization": `Bearer ${token}`,
                "Content-Type": "application/json"
            }
        });
       
        console.log("response status: " + response.status);
        const validateResult = await response.json();
 
        // Send the final validation result back
        return res.status(response.status).json(validateResult);
 
    } catch (error) {
        console.error(error);
        return res.status(500).json({
            error: error.message
        });
    }
};