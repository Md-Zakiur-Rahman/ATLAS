import psutil

print("=== RUNNING PROCESSES ===\n")

for process in psutil.process_iter(['pid', 'name']):

    try:
        print(process.info)

    except:
        pass