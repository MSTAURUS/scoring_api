# scoring api

Запуск:
---------------
~~~
python api.py
~~~

Примеры запросов:
-------------------------
~~~
curl -X POST -H "Content-Type: application/json" -d '{"account": "horns&hoofs", "login": "admin", "method":
"clients_interests", "token":
"936f04336dfc3a5c6f67dfadece649d456eea5941cca92e0f5bbe35b26246c04681ed8f0e942526374e1bd0b87a8a67c8951809bd6780af06e715904e0183c4d",
"arguments": {"client_ids": [1,2,3,4], "date": "20.07.2017"}}' http://127.0.0.1:8080/method/
~~~
~~~
curl -X POST -H "Content-Type: application/json" -d '{"account": "horns&hoofs", "login": "h&f", "method":
"online_score", "token":
"55cc9ce545bcd144300fe9efc28e65d415b923ebb6be1e19d2750a2c03e80dd209a27954dca045e5bb12418e7d89b6d718a9e35af34e14e1d5bcd5a08f21fc95",
"arguments": {"phone": "79175002040", "email": "stupnikov@otus.ru", "first_name": "Стансилав", "last_name":
"Ступников", "birthday": "01.01.1990", "gender": 1}}' http://127.0.0.1:8080/method/
~~~

Тестирование:
------------
~~~
python test.py -v
~~~

🔖 **Домашнее задание/проектная работа выполнено (-на) для курса "[Python Developer. Professional](https://otus.ru/lessons/python-professional/)"**
