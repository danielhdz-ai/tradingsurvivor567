// Vercel Serverless Function para Bitunix Proxy
// Maneja rutas: /api/bitunix/*
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

    try {
        // Rate limiting
        await rateLimiters.bitunix.throttle();
        // Limpiar la URL de cualquier prefijo /api/bitunix
        let fullPath = req.url;
        if (fullPath.startsWith('/api/bitunix')) {
            fullPath = fullPath.replace('/api/bitunix', '');
        }
        
        // Extraer el endpoint y query params
        const [endpoint, queryPart] = fullPath.split('?');
        
        const apiKey = req.headers['x-api-key'];
        const secretKey = req.headers['x-secret-key'];

        // Si no hay credenciales, puede ser una llamada pública
        if (!apiKey || !secretKey) {
            // Endpoint público
            const url = `https://api.bitunix.com${endpoint}${queryPart ? '?' + queryPart : ''}`;
            const response = await fetch(url, {
                method: req.method,
                headers: {
                    'Content-Type': 'application/json'
                }
            });
            const data = await response.json();
            return res.json(data);
        }

        console.log('🔐 Bitunix Auth Request:', {
            endpoint,
            apiKey: apiKey.substring(0, 10) + '...',
            hasSecret: !!secretKey
        });

        // Request autenticada - Bitunix usa firma HMAC SHA256
        const timestamp = (await getServerTime("bitunix")).toString();
        
        // Parsear parámetros existentes
        const existingParams = queryPart ? Object.fromEntries(new URLSearchParams(queryPart)) : {};
        
        // Agregar timestamp y recvWindow a los parámetros
        const allParams = {
            ...existingParams,
            timestamp: timestamp,
            recvWindow: '5000'  // 5 segundos de ventana
        };

        // Ordenar parámetros alfabéticamente y construir query string
        const sortedKeys = Object.keys(allParams).sort();
        const queryParams = sortedKeys
            .map(key => `${key}=${encodeURIComponent(allParams[key])}`)
            .join('&');

        console.log('📝 Query params para firma:', queryParams);

        // Generar firma Bitunix: HMAC SHA256 del query string ordenado
        const signature = crypto
            .createHmac('sha256', secretKey)
            .update(queryParams)
            .digest('hex');

        console.log('✅ Firma generada:', signature.substring(0, 20) + '...');

        // URL final con firma
        const url = `https://api.bitunix.com${endpoint}?${queryParams}&signature=${signature}`;

        console.log('🌐 Enviando request a Bitunix');

        const result = await fetchWithRetry(url, {
            method: req.method,
            headers: {
                'X-BX-APIKEY': apiKey,
                'Content-Type': 'application/json'
            },
            body: req.method === 'POST' && req.body ? JSON.stringify(req.body) : undefined
        });

        if (!result.ok) {
            console.error('❌ Bitunix API Error:', result.status, result.error);
            return res.status(result.status).json(result.error);
        }

        // Validar respuesta de Bitunix
        const validation = validateExchangeResponse(result.data, 'bitunix');
        
        if (!validation.success) {
            console.error('❌ Bitunix Error:', validation.error, 'Code:', validation.code);
            return res.status(400).json({
                success: false,
                error: validation.error,
                code: validation.code
            });
        }

        console.log('✅ Bitunix response OK');
        return res.json(result.data);
    } catch (error) {
        console.error('❌ Bitunix Proxy Error:', error);
        return res.status(500).json({ success: false, error: error.message });
    }
}
