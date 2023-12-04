# Crackme resolver2. Keygen для crackme sampl'а

## Задача - решить crackme. Необходимо найти пару ```{login, password}``` или просто ```{password}``` для конкретного ```login```

## Для корректной работы необоходим ```angr```, ```ida```

### <https://github.com/angr/angr>

### <https://hex-rays.com/ida-free/>

## Reverse область

![alt text](/img/reverse.png)

## Сэмпл crackme находится в папке ```bin```. Результаты выводятся в ```CLI```

## Используйте методы: ```generate_pair``` для генератора пары ```{login, password}``` или ```generate_password``` для генератора ```{password}``` класса ```CrackmeResolver```

## Примеры результатов

```PYTHON
[+] Success: 
        login is: 'Apple'
        password is: 'yyYM'
[+] Success: 
        login is: 'Github'
        password is: 'dcnh'
[+] Success: 
        login is: 'AWML'
        password is: 'vag9d'
```
