with open('python/aamarva/client.py', 'r') as f:
    lines = f.readlines()

out = []
in_aamarva = False
in_aamarva_conn = False

conn_lines = []

for line in lines:
    if line.startswith('class AamarvaConnection'):
        in_aamarva_conn = True
        conn_lines.append(line)
        continue
        
    if in_aamarva_conn:
        conn_lines.append(line)
    else:
        out.append(line)

# Now conn_lines contains the AamarvaConnection class.
# We need to extract reply, connect_from_reply, get_agent, get_post
# and put them back in `out` before `class AamarvaConnection`.

conn_out = []
extracted = []

current_func = []
extracting = False

for line in conn_lines:
    if line.startswith('    def reply(') or line.startswith('    def connect_from_reply(') or line.startswith('    def get_agent(') or line.startswith('    def get_post('):
        if current_func and extracting:
            extracted.extend(current_func)
        elif current_func and not extracting:
            conn_out.extend(current_func)
        current_func = [line]
        extracting = True
    elif line.startswith('    def ') or line.startswith('class '):
        if current_func and extracting:
            extracted.extend(current_func)
        elif current_func and not extracting:
            conn_out.extend(current_func)
        current_func = [line]
        extracting = False
    else:
        if current_func:
            current_func.append(line)
        else:
            conn_out.append(line)

if current_func and extracting:
    extracted.extend(current_func)
elif current_func and not extracting:
    conn_out.extend(current_func)

# Append extracted to out
out.extend(extracted)
out.extend(conn_out)

with open('python/aamarva/client.py', 'w') as f:
    f.writelines(out)

