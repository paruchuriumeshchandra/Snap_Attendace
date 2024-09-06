import qrcode
import os

def generate_qr_code(data, filename):
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(data)
    qr.make(fit=True)
    
    img = qr.make_image(fill='black', back_color='white')
    
    # Ensure the directory exists
    static_dir = os.path.join(os.path.dirname(__file__), 'static')
    if not os.path.exists(static_dir):
        os.makedirs(static_dir)
    
    # Save the image to the static directory
    img.save(os.path.join(static_dir, filename))

if __name__ == '__main__':
    data = "attendance_session_001"  # Example QR code data
    filename = "qr_code.png"  # Name of the file to save
    generate_qr_code(data, filename)
    print(f"QR code saved as {filename}")
