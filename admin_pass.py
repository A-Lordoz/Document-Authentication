import bcrypt
hashed = bcrypt.hashpw(b'MmNJI!Dd%*Rye5yv', bcrypt.gensalt())
print(hashed.decode())