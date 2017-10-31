from sanic import Sanic
from sanic import response as res
from sanic import exceptions as exc
import argon2
import random, string, json

app = Sanic('codeecho')

ph = argon2.PasswordHasher()

config = {}
with open("config.json") as data:
	config = json.loads(data.read())
	data.close()

@app.listener('before_server_start')
def init(sanic, loop):
  """Initialize database before server starts"""
  global db
  from motor.motor_asyncio import AsyncIOMotorClient
  db = AsyncIOMotorClient(
    host=config.get('mongo_host', '0.0.0.0'),
    port=config.get('mongo_port', 27017)
  )[config.get('mongo_db_name', 'codeecho')]

@app.route('/api/auth', methods=['POST'])
async def auth_handler(request):
  """Handles authentication requests"""
  req = request.json
  if not req: raise exc.InvalidUsage("Bad request")

  # Ensure required data is included in the request
  username = req.get('username')
  password = req.get('password')
  if not (username and password): raise exc.InvalidUsage("Bad request")

  # Ensure user exists in database
  user = await db['users'].find_one({ "username": username })
  if not user: raise exc.Forbidden("Invalid credentials")

  # Ensure password is correct
  try:
    ph.verify(user['password'], password)
  except argon2.exceptions.VerifyMismatchError:
    raise exc.Forbidden("Invalid credentials")
  except argon2.exceptions.VerificationError:
    raise exc.ServerError("Password verification failed")

  return res.json({
    "id": str(user['_id']),
    "username": user['username'],
    "email": user['email'],
    "token": user['token']
  })

@app.route('/api/user', methods=['POST'])
async def new_user_handler(request):
  """Handles requests for new users"""
  req = request.json
  if not req: raise exc.InvalidUsage("Bad request")

  # Ensure required data is included in the request
  username = req.get('username')
  email = req.get('email')
  password = req.get('password')
  if not (username and email and password): raise exc.InvalidUsage("Bad request")

  # Ensure user does not already exist in database
  user = await db['users'].find_one({ "username": username })
  if user is not None: return res.json({ "message": "A user with this username already exists", "status": 409 })
  user = await db['users'].find_one({ "email": email })
  if user is not None: return res.json({ "message": "A user with this email already exists", "status": 409 })

  # Hash password
  hashed_pass = ph.hash(password)

  # Generate new token
  token = ''.join(random.SystemRandom().choice(string.ascii_letters + string.digits) for i in range(25))

  # Insert user into database
  user = await db['users'].insert_one({
    "username": username,
    "email": email,
    "password": hashed_pass,
    "token": token
  })

  # Send response
  return res.json({
    "id": str(user.inserted_id),
    "username": username,
    "email": email,
    "token": token
  })

@app.exception(exc.SanicException)
def errors(request, exception):
  """Handles errors"""
  return res.json({ "error": exception.args[0], "status": exception.status_code })

if __name__ == "__main__":
  app.run(
    host=config.get('app_host', '0.0.0.0'),
    port=config.get('app_port', 80),
    debug=True
  )
