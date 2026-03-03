// Vercel Serverless Function para MEXC Proxy
// Maneja: POST /api/proxy-mexc con body { apiKey, secretKey, endpoint, params }
import crypto from 'crypto';
import { 
    rateLimiters, 
    fetchWithRetry, 
    validateExchangeResponse,
    getServerTime,
    setCorsHeaders 
} from './_utils.js';

export default async function handler(req, res) {
    // CORS headers
    setCorsHeaders(res);

    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }

    // Aceptar tanto GET como POST
    if (req.method !== 'POST' && req.method !== 'GET') {
        return res.status(405).json({ success: false, error: 'Method not allowed. Use POST or GET.' });
    }

    try {
        // Rate limiting
        await rateLimiters.mexc.throttle();
        const { apiKey, secretKey, endpoint, params = {} } = req.body;

        if (!apiKey || !secretKey || !endpoint) {
            return res.status(400).json({
                success: false,
                error: 'Faltan apiKey, secretKey o endpoint en el body'
            });
        }

        const timestamp = (await getServerTime("mexc")).toString();
        
        // Ordenar parámetros alfabéticamente para MEXC
        const sortedParams = Object.keys(params)
            .sort()
            .reduce((acc, key) => {
                acc[key] = params[key];
                return acc;
            }, {});

        const queryString = new URLSearchParams(sortedParams).toString();
        
        // Firma MEXC: apiKey + timestamp + sortedParams
        const signString = `${apiKey}${timestamp}${queryString}`;
        const signature = crypto
            .createHmac('sha256', secretKey)
            .update(signString)
            .digest('hex');

        const url = `https://contract.mexc.com${endpoint}${queryString ? '?' + queryString : ''}`;

        console.log('🌐 MEXC Request:', url);

        const result = await fetchWithRetry(url, {
            method: 'GET',
            headers: {
                'ApiKey': apiKey,
                'Request-Time': timestamp,
                'Signature': signature,
                'Content-Type': 'application/json'
            }
        });

        if (!result.ok) {
            console.error('❌ MEXC API Error:', result.status, result.error);
            return res.status(result.status).json(result.error);
        }

        // Validar respuesta de MEXC
        const validation = validateExchangeResponse(result.data, 'mexc');
        
        if (!validation.success) {
            console.error('❌ MEXC Error:', validation.error, 'Code:', validation.code);
            return res.status(400).json({
                success: false,
                error: validation.error,
                code: validation.code
            });
        }

        console.log('✅ MEXC response OK');
        return res.json(result.data);
    } catch (error) {
        console.error('❌ MEXC Proxy Error:', error);
        return res.status(500).json({ success: false, error: error.message });
    }
}
