using System;
using System.Collections.Generic;
using System.Numerics;
using System.Text;

namespace RsaCipherLib
{
    /// <summary>
    /// Упрощённая реализация RSA-шифрования (учебная версия).
    /// Шифрование производится посимвольно над байтами UTF-8 представления строки.
    /// </summary>
    public static class RsaCipher
    {
        /// <summary>
        /// Генерирует пару ключей RSA на основе диапазона для поиска простых чисел.
        /// </summary>
        /// <param name="minPrime">Минимальное простое число (включительно).</param>
        /// <param name="maxPrime">Максимальное простое число (включительно).</param>
        /// <returns>Кортеж (открытая экспонента e, закрытая экспонента d, модуль n).</returns>
        /// <exception cref="ArgumentException">Если в диапазоне недостаточно простых чисел.</exception>
        public static (BigInteger exp, BigInteger d, BigInteger n) GenerateKeys(int minPrime, int maxPrime)
        {
            List<BigInteger> primes = GeneratePrimes(minPrime, maxPrime);
            if (primes.Count < 2)
                throw new ArgumentException("В заданном диапазоне должно быть хотя бы два простых числа.");

            Random rnd = new Random();
            BigInteger p = primes[rnd.Next(primes.Count)];
            BigInteger q = primes[rnd.Next(primes.Count)];
            while (q == p)
                q = primes[rnd.Next(primes.Count)];

            return GenerateKeysFromPrimes(p, q);
        }

        /// <summary>
        /// Генерирует ключи RSA по двум заданным простым числам (используется в тестах).
        /// </summary>
        /// <param name="p">Первое простое число.</param>
        /// <param name="q">Второе простое число.</param>
        /// <returns>Кортеж (e, d, n).</returns>
        public static (BigInteger e, BigInteger d, BigInteger n) GenerateKeysFromPrimes(BigInteger p, BigInteger q)
        {
            BigInteger n = p * q;
            BigInteger phi = (p - 1) * (q - 1);

            BigInteger exp = 65537; // Типичная открытая экспонента
            while (BigInteger.GreatestCommonDivisor(exp, phi) != 1)
                exp += 2; // Ищем взаимно простое с phi

            BigInteger d = ModInverse(exp, phi);
            return (exp, d, n);
        }

        /// <summary>
        /// Зашифровывает строку открытым ключом (e, n).
        /// Возвращает последовательность чисел (шифроблоков), разделённых запятыми.
        /// </summary>
        /// <param name="plainText">Исходный текст (UTF-8).</param>
        /// <param name="exp">Открытая экспонента.</param>
        /// <param name="n">Модуль.</param>
        /// <returns>Строка чисел через запятую.</returns>
        /// <exception cref="ArgumentNullException">Если plainText равен null.</exception>
        /// <exception cref="ArgumentException">Если код какого-либо символа превышает n.</exception>
        public static string Encrypt(string plainText, BigInteger exp, BigInteger n)
        {
            if (plainText == null)
                throw new ArgumentNullException(nameof(plainText));
            if (plainText.Length == 0)
                return string.Empty;

            byte[] utf8Bytes = Encoding.UTF8.GetBytes(plainText);
            List<string> encryptedBlocks = new List<string>(utf8Bytes.Length);

            foreach (byte b in utf8Bytes)
            {
                BigInteger m = b;
                if (m >= n)
                    throw new ArgumentException(
                        $"Код символа '{b}' (0x{b:X2}) больше или равен модулю n={n}. " +
                        "Увеличьте простые числа для получения большего n.");

                BigInteger c = BigInteger.ModPow(m, exp, n);
                encryptedBlocks.Add(c.ToString());
            }

            return string.Join(",", encryptedBlocks);
        }

        /// <summary>
        /// Дешифрует строку шифроблоков (числа через запятую) закрытым ключом (d, n).
        /// </summary>
        /// <param name="cipherText">Строка с числами через запятую.</param>
        /// <param name="d">Закрытая экспонента.</param>
        /// <param name="n">Модуль.</param>
        /// <returns>Исходный текст (UTF-8).</returns>
        /// <exception cref="ArgumentNullException">Если cipherText равен null.</exception>
        /// <exception cref="FormatException">Если строка содержит нечисловые блоки.</exception>
        /// <exception cref="InvalidOperationException">Если дешифрованное значение не помещается в байт.</exception>
        public static string Decrypt(string cipherText, BigInteger d, BigInteger n)
        {
            if (cipherText == null)
                throw new ArgumentNullException(nameof(cipherText));
            if (string.IsNullOrWhiteSpace(cipherText))
                return string.Empty;

            string[] parts = cipherText.Split(',');
            List<byte> decryptedBytes = new List<byte>(parts.Length);

            foreach (string part in parts)
            {
                if (!BigInteger.TryParse(part.Trim(), out BigInteger c))
                    throw new FormatException($"Блок '{part}' не является целым числом.");

                BigInteger m = BigInteger.ModPow(c, d, n);
                if (m > byte.MaxValue)
                    throw new InvalidOperationException(
                        $"Расшифрованное значение {m} превышает 255. Возможно, неверный ключ или данные повреждены.");

                decryptedBytes.Add((byte)m);
            }

            return Encoding.UTF8.GetString(decryptedBytes.ToArray());
        }

        /// <summary>
        /// Вычисляет мультипликативное обратное a по модулю m.
        /// </summary>
        private static BigInteger ModInverse(BigInteger a, BigInteger m)
        {
            if (m == 1) return 0;

            BigInteger m0 = m;
            BigInteger y = 0, x = 1;

            while (a > 1)
            {
                BigInteger q = a / m;
                BigInteger t = m;
                m = a % m;
                a = t;
                t = y;
                y = x - q * y;
                x = t;
            }

            if (x < 0) x += m0;
            return x;
        }

        /// <summary>
        /// Возвращает список простых чисел в заданном диапазоне (простое решето).
        /// </summary>
        /// <param name="min">Нижняя граница.</param>
        /// <param name="max">Верхняя граница.</param>
        private static List<BigInteger> GeneratePrimes(int min, int max)
        {
            if (min < 2) min = 2;
            bool[] isComposite = new bool[max + 1];
            List<BigInteger> primes = new List<BigInteger>();

            for (int i = 2; i <= max; i++)
            {
                if (!isComposite[i])
                {
                    if (i >= min) primes.Add(new BigInteger(i));
                    for (int j = i * 2; j <= max; j += i)
                        isComposite[j] = true;
                }
            }
            return primes;
        }
    }
}