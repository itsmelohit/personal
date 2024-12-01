import express from 'express';
import crypto from 'crypto';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';

const app = express();

// Middleware
app.use(express.json());
app.use(cors());
app.use(helmet());
app.use(morgan('dev'));

// NOWPayments IPN key from environment variable
const IPN_KEY = process.env.NOWPAYMENTS_IPN_KEY || '0wYLrw/Zqu8K7Kbk7VQaGUAS5tbxSS3p';

function verifySignature(payload, signature) {
  // Sort keys alphabetically
  const sortedKeys = Object.keys(payload).sort();
  const sortedPayload = {};
  sortedKeys.forEach(key => {
    sortedPayload[key] = payload[key];
  });

  // Create string from sorted payload
  const payloadString = JSON.stringify(sortedPayload);

  // Create HMAC
  const hmac = crypto.createHmac('sha512', IPN_KEY);
  hmac.update(payloadString);
  const calculatedSignature = hmac.digest('hex');

  return calculatedSignature === signature;
}

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok' });
});

// NOWPayments IPN endpoint
app.post('/api/nowpayments/ipn', (req, res) => {
  try {
    console.log('Received IPN webhook:', {
      headers: req.headers,
      body: req.body
    });

    const signature = req.headers['x-nowpayments-sig'];
    const payload = req.body;

    // Verify signature
    if (!verifySignature(payload, signature)) {
      console.error('Invalid IPN signature');
      return res.status(400).json({ error: 'Invalid signature' });
    }

    // Handle different payment statuses
    switch (payload.payment_status) {
      case 'finished':
        // Payment successful
        console.log('Payment successful:', {
          orderId: payload.order_id,
          paymentId: payload.payment_id,
          amount: payload.price_amount,
          currency: payload.price_currency
        });
        break;

      case 'failed':
        // Payment failed
        console.log('Payment failed:', {
          orderId: payload.order_id,
          paymentId: payload.payment_id,
          error: payload.pay_error
        });
        break;

      case 'partially_paid':
        // Handle partial payment
        console.log('Partial payment received:', {
          orderId: payload.order_id,
          paymentId: payload.payment_id,
          actualAmount: payload.actually_paid,
          expectedAmount: payload.price_amount
        });
        break;

      default:
        console.log('Unhandled payment status:', payload.payment_status);
    }

    res.status(200).json({ status: 'ok' });
  } catch (error) {
    console.error('Error processing IPN:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something broke!' });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`
🚀 IPN handler is running!
   - Local: http://localhost:${PORT}
   - Health check: http://localhost:${PORT}/health
   - IPN endpoint: http://localhost:${PORT}/api/nowpayments/ipn
  `);
});