using Microsoft.VisualStudio.TestTools.UnitTesting;
using RsaCipherLib;
using System;
using System.Numerics;

namespace RsaCipherTests
{
    [TestClass]
    public class RsaCipherTests
    {
        // Фиксированные простые числа для предсказуемости тестов
        private static readonly BigInteger p = 17;
        private static readonly BigInteger q = 11;
        private static readonly BigInteger exp, d, n;

        static RsaCipherTests()
        {
            (exp, d, n) = RsaCipher.GenerateKeysFromPrimes(p, q);
        }

        [TestMethod]
        [Description("Позитивный тест: шифрование/дешифрование возвращает исходный текст")]
        public void EncryptDecrypt_ValidText_Roundtrip()
        {
            // Arrange
            string original = "Hello, World!";

            // Act
            string encrypted = RsaCipher.Encrypt(original, exp, n);
            string decrypted = RsaCipher.Decrypt(encrypted, d, n);

            // Assert
            Assert.AreEqual(original, decrypted, "Дешифрованный текст должен совпадать с исходным.");
            Assert.AreNotEqual(original, encrypted, "Шифротекст не должен совпадать с открытым текстом.");
        }

        [TestMethod]
        [Description("Краевой случай: пустая строка остается пустой")]
        public void Encrypt_EmptyString_ReturnsEmpty()
        {
            string result = RsaCipher.Encrypt("", exp, n);
            Assert.AreEqual("", result);

            string decrypted = RsaCipher.Decrypt("", d, n);
            Assert.AreEqual("", decrypted);
        }

        [TestMethod]
        [Description("Негативный тест: null вызывает ArgumentNullException")]
        public void Encrypt_NullInput_ThrowsArgumentNullException()
        {
            Assert.ThrowsException<ArgumentNullException>(() => RsaCipher.Encrypt(null, exp, n));
            Assert.ThrowsException<ArgumentNullException>(() => RsaCipher.Decrypt(null, d, n));
        }

        [TestMethod]
        [Description("Негативный тест: некорректный формат шифротекста вызывает FormatException")]
        public void Decrypt_InvalidFormat_ThrowsFormatException()
        {
            Assert.ThrowsException<FormatException>(() => RsaCipher.Decrypt("123,abc,456", d, n));
        }

        [TestMethod]
        [Description("Проверка работы с русскими символами (UTF-8)")]
        public void EncryptDecrypt_RussianText_Roundtrip()
        {
            string original = "Привет, студент!";
            string encrypted = RsaCipher.Encrypt(original, exp, n);
            string decrypted = RsaCipher.Decrypt(encrypted, d, n);
            Assert.AreEqual(original, decrypted);
        }

        [TestMethod]
        [Description("Проверка работы со спецсимволами")]
        public void EncryptDecrypt_SpecialChars_Roundtrip()
        {
            string original = "!@#$%^&*()_+-=[]{}|;':\",./<>?";
            string encrypted = RsaCipher.Encrypt(original, exp, n);
            string decrypted = RsaCipher.Decrypt(encrypted, d, n);
            Assert.AreEqual(original, decrypted);
        }

        [TestMethod]
        [Description("Краевой случай: символ с кодом >= n должен вызывать исключение")]
        public void Encrypt_CharacterCodeExceedsN_ThrowsArgumentException()
        {
            // Используем маленькое n через простые числа 2 и 3
            var (e1, _, n1) = RsaCipher.GenerateKeysFromPrimes(2, 3);
            string text = "A"; // 'A' = 65, n1=6, 65>=6 => ошибка
            Assert.ThrowsException<ArgumentException>(() => RsaCipher.Encrypt(text, e1, n1));
        }

        [TestMethod]
        [Description("Проверка генерации ключей при недостатке простых чисел")]
        public void GenerateKeys_InsufficientPrimes_ThrowsArgumentException()
        {
            Assert.ThrowsException<ArgumentException>(() => RsaCipher.GenerateKeys(4, 4));
            Assert.ThrowsException<ArgumentException>(() => RsaCipher.GenerateKeys(90, 96));
        }
    }
}