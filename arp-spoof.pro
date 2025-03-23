TEMPLATE = app
CONFIG += console c++17
CONFIG -= app_bundle
CONFIG -= qt

LIBS += -lpcap

SOURCES += \
        ArgParser.cpp \
        Headers.cpp \
        Packet.cpp \
        main.cpp

HEADERS += \
    ArgParser.h \
    Headers.h \
    Packet.h
