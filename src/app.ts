import express, { Request, Response, Application } from 'express';
import jwt from 'jsonwebtoken';
import * as fs from 'fs';
import * as path from 'path';

const app = express();
const port = 3003;

// Load client configurations
const client = path.join(__dirname, 'client.json');
const clientConfig = JSON.parse(fs.readFileSync(client, 'utf8'));

app.use(express.json()); // To parse JSON bodies in the request

app.get('/', (req: Request, res: Response) => {
  res.send('auth and client service');
});

app.get('/client', (req, res) => {
  console.log(req.headers);
  res.json(clientConfig);
});

app.post('/oauth2', (req: Request, res: Response): any => {
  console.log('req.headers', req.headers);
  if (!req.headers.authorization) {
    console.log('no authorization header');
    res.status(401).json({ error: 'invalid_client' });
    return;
  }
  if (!req.body) {
    res.status(400).json({ error: 'invalid_request, body' });
    return;
  }
  if (req.headers.authorization.split(' ')[0] !== 'Basic') {
    res.status(401).json({ error: 'invalid_client basic' });
    return;
  }

  // read creds from authorization headers
  const [client_id, client_secret] = Buffer.from(
    req.headers.authorization.split(' ')[1],
    'base64'
  )
    .toString()
    .split(':');

  // find client
  const client = clientConfig.find(
    (client: any) => client.client_id === client_id
  );

  // check client secrets
  if (client?.client_secret !== client_secret) {
    res.status(401).json({ error: 'invalid_client sec' });
    return;
  }

  // check grant type
  if (req.body.grant_type !== 'client_credentials') {
    res.status(400).json({ error: 'unsupported_grant_type' });
    return;
  }

  //check scopes
  if (!req.body.scope) {
    res.status(400).json({ error: 'invalid_scope' });
    return;
  }

  if (
    req.body.scope
      .split(' ')
      .some((scope: string) => !client?.scopes.includes(scope))
  ) {
    res.status(400).json({ error: 'invalid_scope' });
    return;
  }

  // generate JWT
  const {
    signing_alg,
    jwks: { k },
    exp,
  } = client;

  const now = Math.floor(Date.now() / 1000);

  const token = jwt.sign(
    {
      client_name: client.client_name,
      client_id,
      scope: req.body.scope.split(' '),
      iat: now,
      nbf: now,
      exp: now + exp,
      iss: 'urn:auth',
    },
    Buffer.from(k, 'base64').toString(),
    { algorithm: signing_alg }
  );

  return res.json({
    access_token: token,
    token_type: 'Bearer',
    expires_in: exp,
  });
});

app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
