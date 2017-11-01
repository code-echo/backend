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
  if not req:
    raise exc.InvalidUsage("Bad request")

  # Ensure required data is included in the request
  username = req.get('username')
  password = req.get('password')
  if not (username and password):
    raise exc.InvalidUsage("Bad request")

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
  if not req:
    raise exc.InvalidUsage("Bad request")

  # Ensure required data is included in the request
  username = req.get('username')
  email = req.get('email')
  password = req.get('password')
  if not (username and email and password):
    raise exc.InvalidUsage("Bad request")

  # Ensure user does not already exist in database
  user = await db['users'].find_one({ "username": username })
  if user is not None:
    return res.json({ "message": "A user with this username already exists", "status": 409 })
  user = await db['users'].find_one({ "email": email })
  if user is not None:
    return res.json({ "message": "A user with this email already exists", "status": 409 })

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

@app.route('/api/user/<user_id:int>', methods=['GET', 'POST'])
async def user_handler(req, user_id):
  """TODO Handles requests for existing users"""
  if not user_id:
    raise exc.InvalidUsage("Bad request")
  #if req.method == 'GET':
  raise exc.NotFound("Soon™")

@app.route('/api/repo', methods=['POST'])
async def new_repo_handler(req):
  """TODO New repo"""
  raise exc.NotFound("Soon™")

# Existing repo
@app.route('/api/repo/<repo_id:int>', methods=['GET', 'POST', 'DELETE'])
async def repo_handler(req, repo_id):
  """Handles requests for existing repositories"""
  if not repo_id:
    raise exc.InvalidUsage("Bad request")

  # Get repository
  if req.method == 'GET':
    # TODO auth check

    repo = await db['repos'].find_one({ "_id": repo_id })
    if not repo:
      raise exc.NotFound("Resource not found")
    
    # Temporary confirmation
    return res.json({ "message": f"You've requested repository ID {repo_id}" })

  # Update repository
  elif req.method == 'POST':
    repo = await db['repos'].find_one({ "_id": repo_id })
    if not repo:
      raise exc.Forbidden("Repository doesn't exist")
    else:
      # TODO Update repo
      pass

  # Delete repository
  elif req.method == 'DELETE':
    repo = await db['repos'].find_one({ "_id": repo_id })
    if not repo:
      raise exc.Forbidden("Repository doesn't exist")
    else:
      return res.json({ "message": "testing" })

@app.exception(exc.SanicException)
def errors(request, exception):
  """Handles errors"""
  return res.json({ "error": exception.args[0], "status": exception.status_code })