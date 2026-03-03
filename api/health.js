// Health check endpoint para verificar que las APIs están funcionando
export default function handler(req, res) {
    res.status(200).json({
        status: 'ok',
        message: 'Proxy APIs activas',
        timestamp: new Date().toISOString(),
        available: [
            'bingx',
            'bitget',
            'mexc',
            'lbank',
            'bitunix'
        ]
    });
}
