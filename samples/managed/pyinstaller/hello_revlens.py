import json
from helper_mod import greet

def main():
    print(json.dumps({"msg": greet("RevLens")}))

if __name__ == "__main__":
    main()
