// Vercel Serverless Function para BingX Proxy
// Maneja rutas: /api/bingx/*
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
        await rateLimiters.bingx.throttle();
        // Limpiar la URL de cualquier prefijo /api/bingx
        let fullPath = req.url;
        if (fullPath.startsWith('/api/bingx')) {
            fullPath = fullPath.replace('/api/bingx', '');
        }
        
        const [endpoint, queryPart] = fullPath.split('?');
        
        const apiKey = req.headers['x-api-key'];
        const secretKey = req.headers['x-secret-key'];

        // Si no hay credenciales, puede ser una llamada pública
        if (!apiKey || !secretKey) {
            // Endpoint público
            const url = `https://open-api.bingx.com${endpoint}${queryPart ? '?' + queryPart : ''}`;
            const result = await fetchWithRetry(url, {
                method: req.method,
                headers: {
                    'Content-Type': 'application/json'
                }
            });
            
            if (!result.ok) {
                return res.status(result.status).json(result.error);
            }
            
            return res.json(result.data);
        }

        console.log('🔐 BingX Auth Request:', {
            endpoint,
            apiKey: apiKey.substring(0, 10) + '...',
            hasSecret: !!secretKey
        });

        // Request autenticada - BingX requiere firma específica
        // Usar timestamp del servidor de BingX (evita errores de sincronización)
        const timestamp = (await getServerTime('bingx')).toString();
        
        // Parsear parámetros existentes
        const existingParams = queryPart ? Object.fromEntries(new URLSearchParams(queryPart)) : {};
        
        // Agregar timestamp a los parámetros
        const allParams = {
            ...existingParams,
            timestamp: timestamp
        };

        // Ordenar parámetros alfabéticamente y construir query string
        const sortedKeys = Object.keys(allParams).sort();
        const queryParams = sortedKeys
            .map(key => `${key}=${allParams[key]}`)
            .join('&');

        console.log('📝 Query params para firma:', queryParams);

        // Generar firma BingX: HMAC SHA256 del query string ordenado
        const signature = crypto
            .createHmac('sha256', secretKey)
            .update(queryParams)
            .digest('hex');

        console.log('✅ Firma generada:', signature.substring(0, 20) + '...');

        // URL final con firma
        const url = `https://open-api.bingx.com${endpoint}?${queryParams}&signature=${signature}`;

        console.log('🌐 Enviando request a BingX');

        const result = await fetchWithRetry(url, {
            method: req.method,
            headers: {
                'X-BX-APIKEY': apiKey,
                'Content-Type': 'application/json'
            },
            body: req.method === 'POST' && req.body ? JSON.stringify(req.body) : undefined
        });

        if (!result.ok) {
            console.error('❌ BingX API Error:', result.status, result.error);
            return res.status(result.status).json(result.error);
        }

        // Validar respuesta de BingX
        const validation = validateExchangeResponse(result.data, 'bingx');
        
        if (!validation.success) {
            console.error('❌ BingX Error:', validation.error, 'Code:', validation.code);
            return res.status(400).json({
                success: false,
                error: validation.error,
                code: validation.code
            });
        }

        console.log('✅ BingX response OK');
        return res.json(result.data);
    } catch (error) {
        console.error('❌ BingX Proxy Error:', error);
        return res.status(500).json({ success: false, error: error.message });
    }
}
