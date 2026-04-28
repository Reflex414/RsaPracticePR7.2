using RsaCipherLib;
using System;
using System.Numerics;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Input;

namespace RsaWpfApp
{
    /// <summary>
    /// Основное окно WPF приложения для демонстрации упрощённого RSA.
    /// </summary>
    public partial class MainWindow : Window
    {
        private BigInteger exp, d, n;
        private bool keysGenerated = false;

        public MainWindow()
        {
            InitializeComponent();
        }

        /// <summary>
        /// Проверка ввода только цифр в поля для простых чисел.
        /// </summary>
        private void NumberValidationTextBox(object sender, TextCompositionEventArgs e)
        {
            Regex regex = new Regex("[^0-9]+");
            e.Handled = regex.IsMatch(e.Text);
        }

        /// <summary>
        /// Генерация пары ключей RSA.
        /// </summary>
        private void btnGenerate_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (!int.TryParse(txtMinPrime.Text, out int min) ||
                    !int.TryParse(txtMaxPrime.Text, out int max))
                {
                    MessageBox.Show("Введите корректные целые числа.", "Ошибка ввода",
                                    MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                if (min < 2 || max <= min)
                {
                    MessageBox.Show("Минимальное значение должно быть >= 2 и меньше максимального.",
                                    "Некорректный диапазон", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                (exp, d, n) = RsaCipher.GenerateKeys(min, max);
                tbPublicKey.Text = $"Открытый ключ: (e={exp}, n={n})";
                tbPrivateKey.Text = $"Закрытый ключ: (d={d}, n={n})";
                keysGenerated = true;

                // Очистка полей для новой пары ключей
                txtEncrypted.Clear();
                txtDecrypted.Clear();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Ошибка генерации ключей: {ex.Message}", "Ошибка",
                                MessageBoxButton.OK, MessageBoxImage.Error);
                keysGenerated = false;
            }
        }

        /// <summary>
        /// Шифрование текста из txtPlain.
        /// </summary>
        private void btnEncrypt_Click(object sender, RoutedEventArgs e)
        {
            if (!keysGenerated)
            {
                MessageBox.Show("Сначала сгенерируйте ключи.", "Информация",
                                MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            try
            {
                string plainText = txtPlain.Text;
                txtEncrypted.Text = RsaCipher.Encrypt(plainText, this.exp, this.n);
                txtDecrypted.Clear();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Ошибка шифрования: {ex.Message}", "Ошибка",
                                MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        /// <summary>
        /// Дешифрование текста из txtEncrypted.
        /// </summary>
        private void btnDecrypt_Click(object sender, RoutedEventArgs e)
        {
            if (!keysGenerated)
            {
                MessageBox.Show("Сначала сгенерируйте ключи.", "Информация",
                                MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            if (string.IsNullOrWhiteSpace(txtEncrypted.Text))
            {
                MessageBox.Show("Нет данных для дешифрования. Сначала зашифруйте текст.",
                                "Пустой шифротекст", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            try
            {
                string decrypted = RsaCipher.Decrypt(txtEncrypted.Text, d, n);
                txtDecrypted.Text = decrypted;
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Ошибка дешифрования: {ex.Message}", "Ошибка",
                                MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
    }
}