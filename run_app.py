import subprocess
import sys

def start_server():
    # Запуск серверной части
    server_process = subprocess.Popen([sys.executable, 'server.py'])
    return server_process

def start_gui():
    # Запуск GUI части
    gui_process = subprocess.Popen([sys.executable, 'gui.py'])
    return gui_process

def main():
    # Запуск сервера и GUI
    server_process = start_server()
    gui_process = start_gui()

    try:
        # Ожидание завершения процессов
        server_process.wait()
        gui_process.wait()
    except KeyboardInterrupt:
        # Обработка завершения по Ctrl+C
        print("Завершение работы приложения...")
        server_process.terminate()
        gui_process.terminate()

if __name__ == "__main__":
    main()
