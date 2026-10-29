from bk_security.api.app import app
import os
import uvicorn

if __name__ == '__main__':
    config = uvicorn.Config(
        app,
        host=os.getenv('BK_SECURITY_HOST', '127.0.0.1'),
        port=int(os.getenv('BK_SECURITY_PORT', '8000')),
        log_level='warning',
        access_log=False,
    )
    server = uvicorn.Server(config)
    app.state.request_shutdown = lambda: setattr(server, 'should_exit', True)
    server.run()
