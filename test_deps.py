# test_deps.py
def test_python_magic():
    """Test python-magic >= 0.4.27"""
    print("\n── python-magic ─────────────────────────────")
    try:
        import magic

        # Description
        m_desc = magic.Magic()
        print(f"  Magic() type   : {type(m_desc)}")

        # MIME
        m_mime = magic.Magic(mime=True)
        print(f"  Magic(mime=True): {type(m_mime)}")

        # Test on this file
        import os, sys
        test_file = sys.executable          # Python interpreter itself
        desc = m_desc.from_file(test_file)
        mime = m_mime.from_file(test_file)
        print(f"  File tested    : {test_file}")
        print(f"  Description    : {desc}")
        print(f"  MIME           : {mime}")
        print("  ✅ python-magic OK")

    except ImportError:
        print("  ❌ python-magic NOT installed → pip install python-magic")
    except Exception as e:
        print(f"  ❌ Error: {e}")


def test_pyssdeep():
    """Test pySSDeep >= 1.0"""
    print("\n── pySSDeep ─────────────────────────────────")
    try:
        import pySSDeep as ssdeep

        # Hash a small byte string
        data = b"Hello from CyberSec Toolkit! " * 50
        h1   = ssdeep.get_fuzzy(data)
        print(f"  get_fuzzy()    : {h1}")

        # Hash from file
        import sys
        test_file = sys.executable
        h2 = ssdeep.get_fuzzy_file(test_file)
        print(f"  get_fuzzy_file : {h2[:60]}...")

        # Similarity
        sim = ssdeep.compare(h1, h1)
        print(f"  compare(h,h)   : {sim}  (expect 100)")

        print("  ✅ pySSDeep OK")

    except ImportError:
        print("  ❌ pySSDeep NOT installed → pip install pySSDeep")
    except Exception as e:
        print(f"  ❌ Error: {e}")


if __name__ == "__main__":
    test_python_magic()
    test_pyssdeep()
    print()