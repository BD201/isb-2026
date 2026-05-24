from tqdm import tqdm
import hashlib


def main():
    target = ""

    for i in range (0, 7):
        found = None
        target += "0"
        print(f"Target length = {len(target)}")
        for i in tqdm(range(1000000)):
            s = f"test_{i}"
            h = hashlib.md5(s.encode()).hexdigest()[:len(target)]
            if h == target:
                found = s
                break
        if found:
            print(f"\nFound: {found} -> {hashlib.md5(found.encode()).hexdigest()[:4]}")
        else:
            print("\nNot found")

if __name__ == "__main__":
    main()