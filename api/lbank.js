// Vercel Serverless Function para LBank Proxy con soporte RSA
// Maneja: POST /api/proxy-lbank
import crypto from 'crypto';
import { 
    rateLimiters, 
    fetchWithRetry, 
    validateExchangeResponse, 
    generateEchostr,
    getServerTime,
    setCorsHeaders 
} from './_utils.js';

export default async function handler(req, res) {
    // CORS headers
    setCorsHeaders(res);

    if (req.method === 'OPTIONS') {
        return res.status(200).end();
    }

    if (req.method !== 'POST') {
        return res.status(405).json({ success: false, error: 'Method not allowed. Use POST.' });
    }

    try {
        // Rate limiting
        await rateLimiters.lbank.throttle();
        
        const { apiKey, privateKey, endpoint, params = {} } = req.body;

        if (!apiKey || !privateKey || !endpoint) {
            return res.status(400).json({
                success: false,
                error: 'Faltan apiKey, privateKey o endpoint en el body'
            });
        }

        // Obtener timestamp sincronizado del servidor de LBank
        const lbankTimestamp = (await getServerTime('lbank')).toString();
        
        // Generar echostr aleatorio de 35 caracteres (entre 30 y 40 como requiere LBank)
        const echostr = generateEchostr(35);
        
        console.log('🔑 LBank echostr generado:', echostr, 'length:', echostr.length);
        
        // 1. Preparar parámetros incluyendo API Key, Timestamp, signature_method y echostr
        const finalParams = {
            ...params,
            api_key: apiKey,
            timestamp: lbankTimestamp,
            signature_method: 'RSA',
            echostr: echostr
        };

        // 2. Ordenar parámetros alfabéticamente por clave
        const sortedKeys = Object.keys(finalParams).sort();
        const signString = sortedKeys
            .map(key => `${key}=${finalParams[key]}`)
            .join('&');

        console.log('📄 String para firmar LBank:', signString);

        // 3. Generar MD5 del string (uppercase)
        const md5Hash = crypto.createHash('md5').update(signString).digest('hex').toUpperCase();
        console.log('🔐 MD5 Hash:', md5Hash);

        // 4. Generar firma RSA-SHA256 del MD5
        let signature = '';
        try {
            const signer = crypto.createSign('RSA-SHA256');
            signer.update(md5Hash);
            // Asegurarse de que la clave privada tenga el formato correcto
            let formattedKey = privateKey;
            if (!formattedKey.includes('-----BEGIN PRIVATE KEY-----')) {
                // Si viene sin cabeceras, intentamos envolverla (aunque se recomienda pegarla entera)
                formattedKey = `-----BEGIN PRIVATE KEY-----\n${privateKey}\n-----END PRIVATE KEY-----`;
            }
            
            signature = signer.sign(formattedKey, 'base64');
        } catch (keyError) {
            console.error('❌ Error en el formato de la Clave Privada RSA:', keyError);
            return res.status(400).json({
                success: false, 
                error: 'Formato de clave privada RSA inválido. Asegúrate de incluir -----BEGIN PRIVATE KEY-----'
            });
        }

        console.log('✅ Firma RSA generada:', signature.substring(0, 20) + '...');

        // 5. Agregar firma a los parámetros
        finalParams.sign = signature;

        // 6. Realizar la petición a LBank con retry logic
        const url = `https://api.lbank.info${endpoint}`;
        
        console.log('📡 Petición a LBank:', url);
        console.log('📋 Parámetros finales:', Object.keys(finalParams).length, 'params');

        const result = await fetchWithRetry(url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: new URLSearchParams(finalParams).toString()
        });

        if (!result.ok) {
            console.error('❌ LBank API Error:', result.status, result.error);
            return res.status(result.status).json({ 
                success: false, 
                error: `LBank API error: ${result.status}`,
                details: result.error
            });
        }

        // Validar respuesta de LBank
        const validation = validateExchangeResponse(result.data, 'lbank');
        
        if (!validation.success) {
            console.error('❌ LBank Error:', validation.error, 'Code:', validation.code);
            return res.status(400).json({
                success: false,
                error: validation.error,
                code: validation.code
            });
        }

        console.log('✅ LBank response OK');
        return res.json(result.data);

    } catch (error) {
        console.error('❌ LBank Proxy Error:', error);
        return res.status(500).json({ 
            success: false, 
            error: error.message 
        });
    }
}
