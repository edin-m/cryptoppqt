#include "mainwindow.h"
#include "ui_mainwindow.h"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    on_aesGenKeyBtn_clicked();
    on_generateKpBtn_clicked();
}

MainWindow::~MainWindow()
{
    delete ui;
}

#include <QDebug>
#include <QMessageBox>

//#include <botan/auto_rng.h>
//#include <botan/ecdsa.h>
//#include <botan/ec_group.h>
//#include <botan/pubkey.h>
//#include <botan/hex.h>
//#include <iostream>

//#include <iostream>
//#include <stdlib.h>
//#include <openssl/evp.h>


//char *base64(const unsigned char *input, int length) {
//  const auto pl = 4*((length+2)/3);
//  auto output = reinterpret_cast<char *>(calloc(pl+1, 1)); //+1 for the terminating null that EVP_EncodeBlock adds on
//  const auto ol = EVP_EncodeBlock(reinterpret_cast<unsigned char *>(output), input, length);
//  if (pl != ol) { std::cerr << "Whoops, encode predicted " << pl << " but we got " << ol << "\n"; }
//  return output;
//}

//unsigned char *decode64(const char *input, int length) {
//  const auto pl = 3*length/4;
//  auto output = reinterpret_cast<unsigned char *>(calloc(pl+1, 1));
//  const auto ol = EVP_DecodeBlock(output, reinterpret_cast<const unsigned char *>(input), length);
//  if (pl != ol) { std::cerr << "Whoops, decode predicted " << pl << " but we got " << ol << "\n"; }
//  return output;
//}




// cryptpp

#include <iostream>
#include <string>

#include "cryptlib.h"
#include "base64.h"
#include "hex.h"
#include "filters.h"
#include "gcm.h"
#include "osrng.h"




#include <iostream>
#include <string>
using namespace std;

#include "cryptlib.h"
#include "filters.h"
#include "files.h"
#include "modes.h"
#include "hex.h"
#include "aes.h"
#include <files.h>
#include <modes.h>
#include <osrng.h>
#include <rsa.h>
#include <sha.h>
using namespace CryptoPP;


static AutoSeededRandomPool grng;





void MainWindow::on_pushButton_clicked()
{
    using namespace CryptoPP;


    Base64Encoder enc;

    const char* data = "wicked sick";
    qDebug() << data;
    enc.Put((const byte*)data, strlen(data));
    enc.MessageEnd();

    std::string encstr;
    encstr.resize(enc.MaxRetrievable());
    enc.Get((byte*)&encstr[0], encstr.size());

    qDebug() << "encoded" << encstr.c_str();



    Base64Decoder dec;
    dec.Put((byte*)&encstr[0], encstr.size());
    dec.MessageEnd();

    std::string decstr;
    decstr.resize(dec.MaxRetrievable());
    dec.Get((byte*)&decstr[0], decstr.size());

    qDebug() << "decoded" << decstr.c_str();



}


std::string encode64(std::string str) {
    using namespace CryptoPP;


    Base64Encoder enc;

    const char* data = "wicked sick";
    qDebug() << data;
    enc.Put((const byte*)&str[0], str.size());
    enc.MessageEnd();

    std::string encstr;
    encstr.resize(enc.MaxRetrievable());
    enc.Get((byte*)&encstr[0], encstr.size());

    return encstr;

}

void MainWindow::on_pushButton_2_clicked()
{
    using namespace CryptoPP;


    AutoSeededRandomPool rnd;

    // Generate a random key
    SecByteBlock key(0x00, AES::DEFAULT_KEYLENGTH);
    rnd.GenerateBlock( key, key.size() );


    // Generate a random IV
    SecByteBlock iv(AES::BLOCKSIZE);
    rnd.GenerateBlock(iv, iv.size());


    byte plainText[] = "Hello! How are you.";
    size_t messageLen = std::strlen((char*)plainText) + 1;


    //////////////////////////////////////////////////////////////////////////
    // Encrypt

    CFB_Mode<AES>::Encryption cfbEncryption(key, key.size(), iv);
    cfbEncryption.ProcessData(plainText, plainText, messageLen);


    qDebug() << encode64(std::string(plainText, plainText+messageLen)).c_str();



    //////////////////////////////////////////////////////////////////////////
    // Decrypt

    CFB_Mode<AES>::Decryption cfbDecryption(key, key.size(), iv);
    cfbDecryption.ProcessData(plainText, plainText, messageLen);




}






QByteArray encode64(QByteArray qdata) {
    Base64Encoder enc(NULL, false);
    enc.Put((const byte*)qdata.data(), qdata.length());
    enc.MessageEnd();

    QByteArray out;
    out.resize(enc.MaxRetrievable());
    char* raw = out.data();
    enc.Get((byte*)raw, out.size());
    qDebug() << "encoded" << out;
    return out;
}

QByteArray decode64(QByteArray data) {
    Base64Decoder dec;
    dec.Put((byte*)data.data(), data.size());
    dec.MessageEnd();

    QByteArray out;
    out.resize(dec.MaxRetrievable());
    char* raw = out.data();
    dec.Get((byte*)raw, out.size());
    qDebug() << "decoded" << out;
    return out;
}



QByteArray encodehex(QByteArray qdata) {
    std::string input = QString::fromUtf8(qdata).toStdString();
    std::string output;

    StringSource(input, true,
                 new HexEncoder(
                     new StringSink(output)
                     )
                 );
    return QString::fromStdString(output).toUtf8();

//    HexEncoder enc;
//    enc.Put((const byte*)qdata.data(), qdata.length());
//    enc.MessageEnd();

//    QByteArray out;
//    out.resize(enc.MaxRetrievable());
//    char* raw = out.data();
//    enc.Get((byte*)raw, out.size());
//    return out;
}

QByteArray decodehex(QByteArray data) {
    HexDecoder dec;
    dec.Put((byte*)data.data(), data.size());
    dec.MessageEnd();

    QByteArray out;
    out.resize(dec.MaxRetrievable());
    char* raw = out.data();
    dec.Get((byte*)raw, out.size());
    return out;
}

QByteArray convert(SecByteBlock& key) {
    return QByteArray((char*)key.BytePtr(), key.size());
}

QByteArray generateAesKeyAsHexStr() {
    SecByteBlock key(0x00, AES::DEFAULT_KEYLENGTH);
    grng.GenerateBlock( key, key.size() );

    std::string keystring;

    StringSource(key, sizeof(key), true,
                 new HexEncoder(
                     new StringSink(keystring)
                     ) // HexEncoder
                 ); // StringSource

    return QByteArray(keystring.c_str(), keystring.size());
}

QByteArray generateAesIV() {
    byte iv[ AES::BLOCKSIZE ];
    grng.GenerateBlock( iv, sizeof(iv) );

    std::string ivstring;

    StringSource(iv, sizeof(iv), true,
                 new HexEncoder(
                     new StringSink(ivstring)
                     ) // HexEncoder
                 ); // StringSource

    return QByteArray(ivstring.c_str(), ivstring.size());
}

QString encryptAesHex(QString hexKey, QString hexIv, QString data) {
    std::string plain = data.toStdString();

    QByteArray keydata = decodehex(hexKey.toLatin1());
    QByteArray ivdata = decodehex(hexIv.toLatin1());

//    SecByteBlock key((const byte*)keydata.data(), keydata.size());

    CFB_Mode<AES>::Encryption enc;
//    enc.SetKeyWithIV(key, key.size(), (const byte*)ivdata.data());
    enc.SetKeyWithIV((const byte*)keydata.data(), keydata.size(), (const byte*)ivdata.data());

    std::string cipher;
    StringSource ssl(plain, true,
                     new StreamTransformationFilter(enc,
                                                    new StringSink(cipher)
                                                    )
                     );

    QString hexcipher = encodehex(QString::fromStdString(cipher).toLatin1());
    return hexcipher;
}


QString decryptAesHex(QString hexKey, QString hexIv, QString hexData) {
    QByteArray keyarr = decodehex(hexKey.toLatin1());
    QByteArray ivarr = decodehex(hexIv.toLatin1());
    QByteArray dataarr = decodehex(hexData.toLatin1());

    SecByteBlock key((const byte*)keyarr.data(), keyarr.size());

    CFB_Mode<AES>::Decryption dec;
    dec.SetKeyWithIV(key, key.size(), (const byte*)ivarr.data());

    std::string plain;
    StringSource ssl(dataarr, true,
                     new StreamTransformationFilter(dec,
                                                    new StringSink(plain)
                                                    )
                     );

    return QString::fromStdString(plain);
}


std::wstring qstringToStdWString(QString& str) {
    return std::wstring((const wchar_t*) str.utf16());
}

QString qstringFromStdWString(const std::wstring& str) {
    return QString::fromWCharArray(str.c_str());
}

std::string encodehex(std::string& str) {
    std::string encoded;
    StringSource s((byte*)&str[0], str.size(), true,
                 new HexEncoder(
                     new StringSink(encoded)
                     ) // HexEncoder
                 ); // StringSource
    return encoded;
}






QByteArray hexEncode(QString tohex) {
    QByteArray arr = encodehex(tohex.toUtf8());
    return encodehex(tohex.toUtf8());
}

QString hexDecode(QByteArray arr) {
    QByteArray out = decodehex(arr);
    return QString::fromUtf8(out.data(), out.size());
}

/**
 * @brief aesCipher
 * @param plaintext
 * @param keyhex
 * @param ivhex
 * @return
 */
QString aesCipher(QString plaintext, QString keyhex, QString ivhex) {
    QByteArray keyarr = decodehex(keyhex.toUtf8());
    QByteArray ivarr = decodehex(ivhex.toUtf8());

    CFB_Mode<AES>::Encryption enc;
    enc.SetKeyWithIV((const byte*)keyarr.data(), keyarr.size(), (const byte*)ivarr.data());

    std::string plain = plaintext.toStdString();
    std::string hexencoded;

    StringSource(plain, true,
                 new StreamTransformationFilter(enc,
                                                new HexEncoder(
                                                    new StringSink(hexencoded)
                                                    )
                                                )
                 );

    return QString::fromStdString(hexencoded);

}

/**
 * @brief aesDecypher
 * @param hexcrypted
 * @param keyhex
 * @param ivhex
 * @return
 */
QString aesDecypher(QString hexcrypted, QString keyhex, QString ivhex) {
    QByteArray keyarr = decodehex(keyhex.toUtf8());
    QByteArray ivarr = decodehex(ivhex.toUtf8());

    CFB_Mode<AES>::Decryption dec;
    dec.SetKeyWithIV((const byte*)keyarr.data(), keyarr.size(), (const byte*)ivarr.data());

    std::string hexencoded;
    std::string deciphered;

    hexencoded = hexcrypted.toStdString();

    StringSource(hexencoded, true,
                 new HexDecoder(
                     new StreamTransformationFilter(dec,
                                                    new StringSink(deciphered)
                                                    )
                     )
                 );

    return QString::fromStdString(deciphered);
}

/**
 * @brief The QCipherAES class
 */
class QCipherAES {
    QByteArray keyhex_;
    QByteArray ivhex_;
public:
    QCipherAES(QByteArray keyhex, QByteArray ivhex) :
        keyhex_(keyhex), ivhex_(ivhex) { }

    QString cipher(QString plaintext) {
        return aesCipher(plaintext, keyhex_, ivhex_);
    }

    QString decipher(QString cipherhex) {
        return aesDecypher(cipherhex, keyhex_, ivhex_);
    }
};



void MainWindow::on_base64EncodeBtn_clicked()
{
    QString str = ui->base64EncodeInput->text();
    QByteArray enc = encode64(str.toLatin1());
    ui->base64EncodeOutput->setText(QString::fromLatin1(enc));
}


void MainWindow::on_base64DecodeBtn_clicked()
{
    QString str = ui->base64DecodeInput->text();
    QByteArray dec = decode64(str.toLatin1());
    ui->base64DecodeOutputLbl->setText(QString::fromLatin1(dec));
}

void MainWindow::on_aesEncryptBtn_clicked()
{

    QString keyhex = ui->aesGenKeyInput->text();
    QString ivhex = ui->aesGenIvBlockInput->text();
    QString toencrypt = ui->aesEncryptInput->text();

    QString encrypted = aesCipher(toencrypt, keyhex, ivhex);

    ui->aesDecryptInput->setText(encrypted);
}

void MainWindow::on_aesGenKeyBtn_clicked()
{
    ui->aesGenKeyInput->setText(generateAesKeyAsHexStr());
    ui->aesGenIvBlockInput->setText(generateAesIV());
}


void MainWindow::on_aesDecryptBtn_clicked()
{
    QString keyhex = ui->aesGenKeyInput->text();
    QString ivhex = ui->aesGenIvBlockInput->text();
    QString hexcrypted = ui->aesDecryptInput->text();

    QString decrypted = aesDecypher(hexcrypted, keyhex, ivhex);
    ui->aesEncryptInput->setText(decrypted);
}

void MainWindow::on_hexEncodeBtn_clicked()
{
    ui->hexDecodeInput->setText(hexEncode(ui->hexEncodeInput->text()));
}

void MainWindow::on_hexDecodeBtn_clicked()
{
    QByteArray bytes = ui->hexDecodeInput->text().toUtf8();
    ui->hexEncodeInput->setText(hexDecode(bytes));
}






//// RSA

template <typename T>
QString rsaKeyToHex(T& rsaKey) {
    ByteQueue queue;
    rsaKey.Save(queue);

    HexEncoder enc;
    queue.CopyTo(enc);
    enc.MessageEnd();

    std::string encstr;
    encstr.resize(enc.MaxRetrievable());
    enc.Get((byte*)&encstr[0], encstr.size());

    return QString::fromStdString(encstr);
}

template<typename T>
T rsaKeyFromHex(QString keyhex) {
    std::string str = keyhex.toStdString();

    HexDecoder dec;
    dec.Put((byte*)&str[0], str.size());
    dec.MessageEnd();

    ByteQueue queue;
    dec.CopyTo(queue);

    T pk;
    pk.Load(queue);
    return pk;
}

void MainWindow::on_generateKpBtn_clicked()
{
    CryptoPP::AutoSeededRandomPool rng;

    CryptoPP::InvertibleRSAFunction params;
    params.GenerateRandomWithKeySize(rng, 1536);

    RSA::PrivateKey privateKey(params);
    RSA::PublicKey publicKey(params);

    ui->rsaPrivateKeyInput->setText(rsaKeyToHex(privateKey));
    ui->rsaPublicKeyInput->setText(rsaKeyToHex(publicKey));
}

void MainWindow::on_rsaEncryptPubKeyBtn_clicked()
{
    try {
        CryptoPP::AutoSeededRandomPool rng;

        QString hexPublic = ui->rsaPublicKeyInput->text();
        RSA::PublicKey publicKey = rsaKeyFromHex<RSA::PublicKey>(hexPublic);


        std::string plain, cipher;
        plain = ui->rsaPlainTextInput->toPlainText().toStdString();

        qDebug() << "plain size" << plain.size();

        RSAES_OAEP_SHA_Encryptor e(publicKey);
        StringSource(plain, true,
                     new PK_EncryptorFilter(rng, e,
                                            new HexEncoder(
                                                new StringSink(cipher)
                                                )
                                            )
                     );

        qDebug() << "cipher" << cipher.size();

        QString hexencrypted = QString::fromStdString(cipher);
        ui->rsaEncryptedTextInput->setPlainText(hexencrypted);

    } catch(const Exception& ex) {
        qDebug() << ex.what();
        QMessageBox box;
        box.setText(ex.what());
        box.exec();
    }

}

void MainWindow::on_rsaDecryptPrivKeyBtn_clicked()
{
    CryptoPP::AutoSeededRandomPool rng;

    QString hexPrivate = ui->rsaPrivateKeyInput->text();
    RSA::PrivateKey privateKey = rsaKeyFromHex<RSA::PrivateKey>(hexPrivate);

    std::string plain, cipher, decrypted_data;
    cipher = ui->rsaEncryptedTextInput->toPlainText().toStdString();

    RSAES_OAEP_SHA_Decryptor d(privateKey);
    StringSource(cipher, true,
                 new HexDecoder(
                     new PK_DecryptorFilter(rng, d,
                                            new StringSink(decrypted_data)
                                            )
                     )
                 );

    QString decrstr = QString::fromStdString(decrypted_data);
    ui->rsaPlainTextInput->setPlainText(decrstr);
}
