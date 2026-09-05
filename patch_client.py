import re

with open('python/aamarva/client.py', 'r') as f:
    content = f.read()

# The class AamarvaConnection starts with:
# class AamarvaConnection(Connection):
#     def __init__(self, client: Aamarva, **kwargs):

# We need to extract the methods: reply, connect_from_reply, get_agent, get_post
# and move them to Aamarva class.

# Actually, it's easier to just rebuild client.py correctly.
