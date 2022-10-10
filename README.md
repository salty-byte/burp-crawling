# burp-crawling

![build](https://github.com/salty-byte/burp-crawling/workflows/build/badge.svg)
![test](https://github.com/salty-byte/burp-crawling/workflows/test/badge.svg)

クローリングサポート用の [BurpSuite](https://portswigger.net/burp/releases) 拡張機能。

## キャプチャ

![メイン画面](./images/main.jpg)

## 前提

- Java 11 (or later)
- BurpSuite 2020.1 (or later)

## ビルド

- for Windows

```ps
.\gradlew.bat clean fatJar
```

- for Linux

```sh
./gradlew clean fatJar
```

## ライセンス

[MIT](/LICENSE)

## 作成者

[salty-byte](https://github.com/salty-byte)
