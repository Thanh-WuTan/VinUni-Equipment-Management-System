from web import create_app
from flask import send_from_directory


app = create_app()

if __name__ == '__main__':
    @app.route('/images/<path:path>')
    def send_report(path):
        return send_from_directory('images', path)
    app.run(debug = True)

