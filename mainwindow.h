#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void on_pushButton_clicked();

    void on_pushButton_2_clicked();

    void on_base64EncodeBtn_clicked();

    void on_base64DecodeBtn_clicked();

    void on_aesEncryptBtn_clicked();

    void on_aesGenKeyBtn_clicked();

    void on_aesDecryptBtn_clicked();

    void on_hexEncodeBtn_clicked();

    void on_hexDecodeBtn_clicked();

    void on_generateKpBtn_clicked();

    void on_rsaEncryptPubKeyBtn_clicked();

    void on_rsaDecryptPrivKeyBtn_clicked();

private:
    Ui::MainWindow *ui;
};
#endif // MAINWINDOW_H
