import sys




if __name__ == "__main__":
    message = "Forging RSA signatures using bleichenbacker attack!"
    message_utf8 = message.encode('utf-8')

    with open('msg.utf8', 'wb') as file:
        file.write(message_utf8)
    
    signature_hex = "21294e170c8145354183f9fd86e3979d3513a5f045378e8279a774776fa7696c02616c8724cffdc32b0c205d02336d2639303219a8eaeea35b945484e083a187fa80530112a432851c8a06bbb6d3b882f133e4bd37eea2d15113cc06ae933b9f2e0655bd80be7fdd2d593fa4b7d772b3babce2b2f011713c7cca3c6e81f8c090"
    signature_bytes = bytes.fromhex(signature_hex)
    with open('msg_sig.sig', 'wb') as file:
        file.write(signature_bytes)
    

