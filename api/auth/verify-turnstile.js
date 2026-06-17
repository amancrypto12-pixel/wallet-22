export default async function handler(request, response) {
  if (request.method !== 'POST') {
    response.setHeader('Allow', 'POST');
    return response.status(405).json({
      success: false,
      message: 'Method not allowed.',
    });
  }

  const secret = process.env.TURNSTILE_SECRET_KEY;
  if (!secret) {
    return response.status(500).json({
      success: false,
      message: 'Turnstile service not configured.',
    });
  }

  const token = request.body?.token;
  if (!token || typeof token !== 'string') {
    return response.status(400).json({
      success: false,
      message: 'Please complete human verification.',
    });
  }

  try {
    const remoteIp =
      request.headers['cf-connecting-ip'] ||
      request.headers['x-forwarded-for'] ||
      request.socket?.remoteAddress;
    const verification = await fetch(
      'https://challenges.cloudflare.com/turnstile/v0/siteverify',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          secret,
          response: token,
          remoteip: Array.isArray(remoteIp) ? remoteIp[0] : remoteIp,
        }),
      },
    );
    const result = await verification.json();
    if (!result.success) {
      console.error('Turnstile verification failed', result['error-codes']);
      return response.status(403).json({
        success: false,
        message: 'Please complete human verification.',
        errors: result['error-codes'] || [],
      });
    }

    return response.status(200).json({ success: true });
  } catch (error) {
    console.error('Turnstile verification error', error);
    return response.status(500).json({
      success: false,
      message: 'Please complete human verification.',
    });
  }
}
