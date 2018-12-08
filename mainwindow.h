#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void on_encryptButton_clicked();

    void on_decryptButton_clicked();

    void on_clearPlainButton_clicked();

    void on_clearCipherButton_clicked();

private:
    Ui::MainWindow *ui;
};

#endif // MAINWINDOW_H
