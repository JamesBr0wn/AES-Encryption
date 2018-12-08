#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "algorithm.h"

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    setWindowFlags(windowFlags()&~Qt::WindowMaximizeButtonHint);
    setFixedSize(this->width(),this->height());
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_encryptButton_clicked()
{
    std::string key = ui->secretKeyEdit->text().toStdString();
    std::string plainText = ui->plainTextEdit->toPlainText().toStdString();
    EncryptType encryptType = EncryptType(ui->typeBox->currentIndex());
    WorkMode workMode = WorkMode(ui->modeBox->currentIndex());
    AESWrapper wrapper(encryptType, workMode);
    wrapper.SetKey(key);
    std::string cipherText = wrapper.Encrypt(plainText);
    ui->cipherTextEdit->setText(QString::fromStdString(cipherText));
}

void MainWindow::on_decryptButton_clicked()
{
    std::string key = ui->secretKeyEdit->text().toStdString();
    std::string cipherText = ui->cipherTextEdit->toPlainText().toStdString();
    EncryptType encryptType = EncryptType(ui->typeBox->currentIndex());
    WorkMode workMode = WorkMode(ui->modeBox->currentIndex());
    AESWrapper wrapper(encryptType, workMode);
    wrapper.SetKey(key);
    std::string plainText = wrapper.Decrypt(cipherText);
    ui->plainTextEdit->setText(QString::fromStdString(plainText));
}

void MainWindow::on_clearPlainButton_clicked()
{
    ui->plainTextEdit->clear();
}

void MainWindow::on_clearCipherButton_clicked()
{
    ui->cipherTextEdit->clear();
}
