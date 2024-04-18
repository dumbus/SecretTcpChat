# Передача текстовых данных с помощью протокола TCP с подменой IP-адресов источника

## Необходимое ПО:

- Git - [Скачать и установить Git](https://git-scm.com/downloads).
- Python3 - [Скачать и установить Python](https://www.python.org/downloads/).
- Pip - [Скачать и установить Pip](https://pypi.org/project/pip/).

## Загрузка приложения:

### 1. Склонировать репозиторий:
```
git clone https://github.com/dumbus/SecretTcpChat.git
```
### 2. Перейти в директорию проекта:
```
cd SecretTcpChat
```
### 3. Установить необходимые библиотеки:

```
pip install Scapy
```

## Использование приложения:

### 1. Запуск приложения возможен в 2 режимах

#### Режим разработки (dev):
- Пакеты отправляются через сетевой интерфейс loopback
- IP-адрес сервера при запуске клиентов получается автоматически с помощью Scapy

#### Режим продакшена (prod):
- Пакеты отправляются через используемый в данный момент сетеывой интерфейс (автоматически определяется с помощью Scapy) 
- IP-адрес сервера при запуске клиентов указывается вручную

### 2. Запустить сервер

#### Запуск для Windows:
```
python server.py <dev | prod> win
```

#### Запуск для Linux:
```
python3 server.py <dev | prod> unix
```

### 3. Запустить клиентов

#### Запуск для Windows:
```
python client.py <dev | prod> win
```

#### Запуск для Linux:
```
python3 client.py <dev | prod> unix
```

### 4. Обмен текстовыми данными

- После подключения к серверу клиенты могут обмениваться текстовыми данными в режиме реального времени
- Клиенты получают сообщения о подключении и отключении других клиентов от чата
- Команда ```.exit``` инициирует "мягкое" отключение клиента от сервера
- В случае возникновения ошибок (разрыва соединения, отключения сервера и т.д.) клиенты экстренно завершают свою работу с получением соответствующего сообщения в консоли

### Скрытие IP-адресов источника

IP-адреса источника для всех сетевых пакетов, отправляемых в ходе обмена данными пользователями заменяются на случайные.

Пример результатов работы программы:
![image](https://github.com/dumbus/SecretTcpChat/assets/79057837/354eff35-c78a-419d-b6b3-0a3afb435fc6)

## Дополнительная важная информация

```
Если нужно протестировать приложение локально, нужно использовать исключительно режим **dev**, использование режима **prod** с ручным указанием ip-адреса интерфейса loopback не сработает, так как в режиме **prod** приложение автоматически определяет интерфейс для отправки пакетов. 
Возникнет несоответствие ip-адреса интерфейса, и приложение работать не будет.
````