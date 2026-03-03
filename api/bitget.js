// Vercel Serverless Function para Bitget Proxy
// Maneja rutas: /api/bitget/*
import crypto from 'crypto';
import {
    rateLimiters,
    fetchWithRetry,
    validateExchangeResponse,
    getServerTime,
    setCorsHeaders
} from './_utils.js';

export default async function handler(req, res) {
    setCorsHeaders(res);
    if (req.method === 'OPTIONS') return res.status(200).end();

    try {
        await rateLimiters.bitget.throttle();
        
        let endpoint = req.url;
        if (endpoint.startsWith('/api/bitget')) endpoint = endpoint.replace('/api/bitget', '');
        
        const apiKey = req.headers['x-api-key'];
        const secretKey = req.headers['x-secret-key'];
        const passphrase = req.headers['x-passphrase'];
        
        if (!apiKey || !secretKey || !passphrase) {
            return res.status(400).json({ success: false, error: 'Faltan headers x-api-key, x-secret-key, x-passphrase' });
        }

        const method = req.method.toUpperCase();
        // Usar timestamp del servidor con mejor sincronización
        const serverTime = await getServerTime('bitget');
        // Agregar pequeño buffer de 1 segundo para compensar latencia
        const timestamp = (serverTime + 1000).toString();

        let bodyStr = '';
        if (method === 'POST' && req.body && Object.keys(req.body).length > 0) {
            bodyStr = JSON.stringify(req.body);
        }

        const prehash = timestamp + method + endpoint + bodyStr;
        const signature = crypto.createHmac('sha256', secretKey).update(prehash).digest('base64');

        const url = 'https://api.bitget.com' + endpoint;

        const fetchOptions = {
            method: method,
            headers: {
                'ACCESS-KEY': apiKey,
                'ACCESS-SIGN': signature,
                'ACCESS-TIMESTAMP': timestamp,
                'ACCESS-PASSPHRASE': passphrase,
                'Content-Type': 'application/json',
                'locale': 'en-US'
            }
        };

        if (bodyStr) fetchOptions.body = bodyStr;

        const result = await fetchWithRetry(url, fetchOptions);

        if (!result.ok) return res.status(result.status).json(result.error);

        const validation = validateExchangeResponse(result.data, 'bitget');     
        if (!validation.success) return res.status(400).json({ success: false, error: validation.error, code: validation.code });

        return res.json(result.data);
    } catch (error) {
        console.error('Error Bitget proxy:', error);
        return res.status(500).json({ success: false, error: error.message });  
    }
}
