import tkinter as tk
from tkinter import ttk, messagebox
import csv
import datetime
import socket
import threading
import os
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.neural_network import MLPClassifier
import pandas as pd
from sklearn.preprocessing import StandardScaler

class FirewallApp:
    def __init__(self, root):
        # Инициализация основного окна приложения
        self.root = root
        self.root.title("Детектор Сетевых Атак")  # Установка заголовка окна
        self.rules = []  # Список правил файрвола
        self.create_widgets()  # Создание элементов интерфейса
        self.log_file = "firewall_logs.csv"  # Имя файла для логов
        # Если файл логов не существует, создаем его и добавляем заголовки
        if not os.path.exists(self.log_file):
            with open(self.log_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(["Дата", "Время", "IP", "Действие"])
        self.start_firewall()  # Запуск файрвола в отдельном потоке
        self.model = None  # Модель нейронной сети
        self.scaler = None  # Масштабировщик данных

    def create_widgets(self):
        # Создание и размещение всех элементов интерфейса
        frame = ttk.Frame(self.root, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)

        # Фрейм для добавления новых правил
        rule_frame = ttk.LabelFrame(frame, text="Добавить Правило")
        rule_frame.pack(fill=tk.X, pady=5)

        # Метка и комбобокс для выбора действия (разрешить/запретить)
        ttk.Label(rule_frame, text="Действие:").grid(row=0, column=0, padx=5, pady=5)
        self.action_var = tk.StringVar()
        action_combo = ttk.Combobox(rule_frame, textvariable=self.action_var, values=["разрешить", "запретить"])
        action_combo.grid(row=0, column=1, padx=5, pady=5)

        # Метка и поле ввода для IP-адреса
        ttk.Label(rule_frame, text="IP Адрес:").grid(row=0, column=2, padx=5, pady=5)
        self.ip_var = tk.StringVar()
        ip_entry = ttk.Entry(rule_frame, textvariable=self.ip_var)
        ip_entry.grid(row=0, column=3, padx=5, pady=5)

        # Кнопка для добавления правила
        add_btn = ttk.Button(rule_frame, text="Добавить Правило", command=self.add_rule)
        add_btn.grid(row=0, column=4, padx=5, pady=5)

        # Фрейм для отображения текущих правил
        rules_frame = ttk.LabelFrame(frame, text="Текущие Правила")
        rules_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        self.rules_list = tk.Listbox(rules_frame)
        self.rules_list.pack(fill=tk.BOTH, expand=True)

        # Фрейм для кнопок анализа логов, построения графика и обнаружения атак
        log_frame = ttk.Frame(frame)
        log_frame.pack(fill=tk.X, pady=5)

        analyze_btn = ttk.Button(log_frame, text="Анализировать Логи", command=self.analyze_logs)
        analyze_btn.pack(side=tk.LEFT, padx=5)

        plot_btn = ttk.Button(log_frame, text="Показать График", command=self.show_plot)
        plot_btn.pack(side=tk.LEFT, padx=5)

        detect_btn = ttk.Button(log_frame, text="Обнаружить Атаки", command=self.detect_attacks)
        detect_btn.pack(side=tk.LEFT, padx=5)

    def add_rule(self):
        # Метод для добавления нового правила
        action = self.action_var.get()
        ip = self.ip_var.get()
        if action and ip:
            self.rules.append((action, ip))  # Добавляем правило в список
            self.rules_list.insert(tk.END, f"{action} {ip}")  # Отображаем правило в Listbox
            self.action_var.set("")  # Очищаем поле выбора действия
            self.ip_var.set("")  # Очищаем поле ввода IP
        else:
            # Вывод предупреждения, если поля не заполнены
            messagebox.showwarning("Ошибка Ввода", "Пожалуйста, введите и действие, и IP адрес.")

    def start_firewall(self):
        # Запуск файрвола в отдельном потоке
        threading.Thread(target=self.firewall_thread, daemon=True).start()

    def firewall_thread(self):
        # Основной цикл работы файрвола
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.bind(('0.0.0.0', 9999))  # Привязка к порту 9999 на всех интерфейсах
            server.listen(5)  # Прослушивание входящих соединений
            while True:
                client, addr = server.accept()  # Принятие соединения
                ip = addr[0]  # Получение IP-адреса клиента
                action = self.check_rules(ip)  # Определение действия (разрешить/запретить)
                now = datetime.datetime.now()  # Текущее время
                # Запись события в лог-файл
                with open(self.log_file, 'a', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow([now.date(), now.time(), ip, action])
                # Отправка сообщения клиенту в зависимости от действия
                if action == "разрешить":
                    client.send("Соединение разрешено.\n".encode('utf-8'))
                    client.close()
                else:
                    client.send("Соединение запрещено.\n".encode('utf-8'))
                    client.close()
        except Exception as e:
            # Вывод ошибки, если что-то пошло не так
            messagebox.showerror("Ошибка Файрвола", f"Произошла ошибка в файрволе:\n{e}")

    def check_rules(self, ip):
        # Проверка IP-адреса по списку правил
        for rule in self.rules:
            if rule[1] == ip:
                return rule[0]  # Возвращаем действие (разрешить/запретить)
        return "запретить"  # По умолчанию запрещаем соединение

    def analyze_logs(self):
        # Метод для анализа логов и обучения модели нейронной сети
        try:
            df = pd.read_csv(self.log_file, encoding='utf-8')  # Чтение лог-файла
            if df.empty:
                # Если файл пуст, уведомляем пользователя
                messagebox.showinfo("Анализ Логов", "Файл логов пуст.")
                return
            # Создание столбца с полным временем запроса
            df['Timestamp'] = pd.to_datetime(df['Дата'].astype(str) + ' ' + df['Время'].astype(str))
            df.sort_values('Timestamp', inplace=True)  # Сортировка по времени
            # Группировка данных по IP-адресам и расчет статистик
            ip_stats = df.groupby('IP').agg(
                Total_Requests=('Действие', 'count'),
                Denied_Requests=('Действие', lambda x: (x == 'запретить').sum()),
                First_Request=('Timestamp', 'min'),
                Last_Request=('Timestamp', 'max')
            ).reset_index()
            # Расчет коэффициента отказов и времени активности
            ip_stats['Deny_Rate'] = ip_stats['Denied_Requests'] / ip_stats['Total_Requests']
            ip_stats['Active_Time'] = (ip_stats['Last_Request'] - ip_stats['First_Request']).dt.total_seconds()
            ip_stats.fillna(0, inplace=True)  # Заполнение пропущенных значений нулями
            # Выбор признаков для модели
            features = ip_stats[['Total_Requests', 'Denied_Requests', 'Deny_Rate', 'Active_Time']]
            # Определение меток (1 - атака, 0 - нормальное поведение)
            labels = ip_stats['Denied_Requests'].apply(lambda x: 1 if x > 10 else 0)
            if features.empty:
                # Если нет признаков для анализа, уведомляем пользователя
                messagebox.showinfo("Анализ Логов", "Недостаточно данных для анализа.")
                return
            self.scaler = StandardScaler()  # Инициализация масштабировщика
            X_scaled = self.scaler.fit_transform(features)  # Масштабирование признаков
            # Разделение данных на обучающую и тестовую выборки
            X_train, X_test, y_train, y_test = train_test_split(X_scaled, labels, test_size=0.2, random_state=42)
            clf = MLPClassifier(hidden_layer_sizes=(50,), max_iter=1000, random_state=42)  # Инициализация модели
            clf.fit(X_train, y_train)  # Обучение модели
            acc = clf.score(X_test, y_test)  # Оценка точности модели
            self.model = clf  # Сохранение модели
            # Вывод точности модели пользователю
            messagebox.showinfo("Точность Модели", f"Точность: {acc*100:.2f}%")
        except FileNotFoundError:
            # Ошибка, если файл логов не найден
            messagebox.showerror("Ошибка Файла", "Файл логов не найден.")
        except pd.errors.EmptyDataError:
            # Ошибка, если файл логов пуст
            messagebox.showinfo("Анализ Логов", "Файл логов пуст.")
        except Exception as e:
            # Любые другие ошибки при анализе логов
            messagebox.showerror("Ошибка Анализа Логов", f"Произошла ошибка при анализе логов:\n{e}")

    def show_plot(self):
        # Метод для отображения графика запросов от IP-адресов
        try:
            df = pd.read_csv(self.log_file, encoding='utf-8')  # Чтение лог-файла
            if df.empty:
                # Если файл пуст, уведомляем пользователя
                messagebox.showinfo("Показать График", "Файл логов пуст.")
                return
            counts = df['IP'].value_counts()  # Подсчет количества запросов от каждого IP
            if counts.empty:
                # Если нет данных для графика, уведомляем пользователя
                messagebox.showinfo("Показать График", "Нет данных для построения графика.")
                return
            # Построение столбчатой диаграммы
            counts.plot(kind='bar', figsize=(10,6))
            plt.xlabel('IP Адрес')  # Подпись оси X
            plt.ylabel('Количество Запросов')  # Подпись оси Y
            plt.title('Запросы от IP Адресов')  # Заголовок графика
            plt.tight_layout()  # Автоматическое размещение элементов графика
            plt.show()  # Отображение графика
        except FileNotFoundError:
            # Ошибка, если файл логов не найден
            messagebox.showerror("Ошибка Файла", "Файл логов не найден.")
        except pd.errors.EmptyDataError:
            # Ошибка, если файл логов пуст
            messagebox.showinfo("Показать График", "Файл логов пуст.")
        except Exception as e:
            # Любые другие ошибки при построении графика
            messagebox.showerror("Ошибка Построения Графика", f"Произошла ошибка при построении графика:\n{e}")

    def detect_attacks(self):
        # Метод для обнаружения потенциальных атак с помощью обученной модели
        try:
            if self.model is None or self.scaler is None:
                # Если модель не обучена, уведомляем пользователя
                messagebox.showwarning("Модель Не Обучена", "Пожалуйста, сначала проанализируйте логи для обучения модели.")
                return
            df = pd.read_csv(self.log_file, encoding='utf-8')  # Чтение лог-файла
            if df.empty:
                # Если файл пуст, уведомляем пользователя
                messagebox.showinfo("Обнаружить Атаки", "Файл логов пуст.")
                return
            # Создание столбца с полным временем запроса
            df['Timestamp'] = pd.to_datetime(df['Дата'].astype(str) + ' ' + df['Время'].astype(str))
            df.sort_values('Timestamp', inplace=True)  # Сортировка по времени
            # Группировка данных по IP-адресам и расчет статистик
            ip_stats = df.groupby('IP').agg(
                Total_Requests=('Действие', 'count'),
                Denied_Requests=('Действие', lambda x: (x == 'запретить').sum()),
                First_Request=('Timestamp', 'min'),
                Last_Request=('Timestamp', 'max')
            ).reset_index()
            # Расчет коэффициента отказов и времени активности
            ip_stats['Deny_Rate'] = ip_stats['Denied_Requests'] / ip_stats['Total_Requests']
            ip_stats['Active_Time'] = (ip_stats['Last_Request'] - ip_stats['First_Request']).dt.total_seconds()
            ip_stats.fillna(0, inplace=True)  # Заполнение пропущенных значений нулями
            # Выбор признаков для модели
            features = ip_stats[['Total_Requests', 'Denied_Requests', 'Deny_Rate', 'Active_Time']]
            if features.empty:
                # Если нет признаков для анализа, уведомляем пользователя
                messagebox.showinfo("Обнаружить Атаки", "Недостаточно данных для обнаружения атак.")
                return
            X_scaled = self.scaler.transform(features)  # Масштабирование признаков
            predictions = self.model.predict(X_scaled)  # Предсказание с использованием модели
            attack_ips = ip_stats[predictions == 1]['IP'].tolist()  # Список IP-адресов, классифицированных как атаки
            if attack_ips:
                # Если обнаружены потенциальные атаки, выводим список
                attacks = "\n".join(attack_ips)
                messagebox.showinfo("Обнаруженные Атаки", f"Потенциальные источники атак:\n{attacks}")
            else:
                # Если атак не обнаружено, уведомляем пользователя
                messagebox.showinfo("Обнаруженные Атаки", "Потенциальные атаки не обнаружены.")
        except FileNotFoundError:
            # Ошибка, если файл логов не найден
            messagebox.showerror("Ошибка Файла", "Файл логов не найден.")
        except pd.errors.EmptyDataError:
            # Ошибка, если файл логов пуст
            messagebox.showinfo("Обнаружить Атаки", "Файл логов пуст.")
        except Exception as e:
            # Любые другие ошибки при обнаружении атак
            messagebox.showerror("Ошибка Обнаружения Атак", f"Произошла ошибка при обнаружении атак:\n{e}")

if __name__ == "__main__":
    root = tk.Tk()  # Создание основного окна приложения
    app = FirewallApp(root)  # Инициализация приложения
    root.mainloop()  # Запуск главного цикла обработки событий
