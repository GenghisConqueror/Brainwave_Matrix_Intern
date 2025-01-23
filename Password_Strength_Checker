#include <iostream>
#include <string>
#include <regex>
#include <unordered_set>
#include <cmath>
#include <vector>
#include <algorithm>
#include <map>
#include <chrono>
#include <random>

class PasswordStrengthChecker {
public:
    struct Result {
        std::string strength;
        std::vector<std::string> feedback;
        double entropy;
        std::map<std::string, double> detailedMetrics;
        std::string ratingBadge;
    };

    static Result checkPasswordStrength(const std::string &password) {
        Result result;
        int score = 0;

        result.ratingBadge = generateRatingBadge();

        result.detailedMetrics["Length"] = password.length();
        if (password.length() < 8) {
            result.feedback.push_back("Password is too short. Use at least 8 characters.");
        } else if (password.length() >= 16) {
            score += 3;
        } else if (password.length() >= 12) {
            score += 2;
        } else {
            score += 1;
        }

        result.detailedMetrics["Lowercase"] = std::any_of(password.begin(), password.end(), ::islower) ? 1 : 0;
        if (!result.detailedMetrics["Lowercase"]) {
            result.feedback.push_back("Add lowercase letters to strengthen your password.");
        } else {
            score += 1;
        }

        result.detailedMetrics["Uppercase"] = std::any_of(password.begin(), password.end(), ::isupper) ? 1 : 0;
        if (!result.detailedMetrics["Uppercase"]) {
            result.feedback.push_back("Add uppercase letters to strengthen your password.");
        } else {
            score += 1;
        }

        result.detailedMetrics["Digits"] = std::any_of(password.begin(), password.end(), ::isdigit) ? 1 : 0;
        if (!result.detailedMetrics["Digits"]) {
            result.feedback.push_back("Add numbers to make your password stronger.");
        } else {
            score += 1;
        }

        result.detailedMetrics["SpecialCharacters"] = std::regex_search(password, std::regex("[!@#$%^&*(),.?\\\":{}|<>]")) ? 1 : 0;
        if (!result.detailedMetrics["SpecialCharacters"]) {
            result.feedback.push_back("Include special characters like @, #, $, etc., for better security.");
        } else {
            score += 2;
        }

        if (std::regex_search(password, std::regex("(.)\\1{2,}"))) {
            result.feedback.push_back("Avoid repeated characters or sequences.");
            score -= 1;
        }

        std::unordered_set<std::string> commonWords = {"password", "123456", "qwerty", "abc123", "letmein", "admin"};
        if (commonWords.find(password) != commonWords.end()) {
            result.feedback.push_back("Avoid using common or easily guessable passwords.");
            score -= 3;
        }

        double entropy = calculateEntropy(password);
        result.entropy = entropy;
        result.detailedMetrics["Entropy"] = entropy;
        if (entropy < 40) {
            result.feedback.push_back("Increase password complexity to raise entropy.");
            score -= 2;
        } else if (entropy > 90) {
            score += 3;
        }

        std::unordered_set<std::string> breachedDatabase = {"123456", "password1", "iloveyou", "admin123"};
        if (breachedDatabase.find(password) != breachedDatabase.end()) {
            result.feedback.push_back("This password has appeared in breached databases. Avoid using compromised passwords.");
            score -= 3;
        }

        if (score >= 8) {
            result.strength = "Very Strong";
        } else if (score >= 5) {
            result.strength = "Strong";
        } else if (score >= 3) {
            result.strength = "Moderate";
        } else {
            result.strength = "Weak";
        }

        return result;
    }

private:
    static double calculateEntropy(const std::string &password) {
        std::unordered_set<char> uniqueChars(password.begin(), password.end());
        double poolSize = 0;

        if (std::any_of(password.begin(), password.end(), ::islower)) poolSize += 26;
        if (std::any_of(password.begin(), password.end(), ::isupper)) poolSize += 26;
        if (std::any_of(password.begin(), password.end(), ::isdigit)) poolSize += 10;
        if (std::regex_search(password, std::regex("[!@#$%^&*(),.?\\\":{}|<>]"))) poolSize += 32;

        return password.length() * std::log2(poolSize);
    }

    static std::string generateRatingBadge() {
        static const std::vector<std::string> badges = {
            "Security Guru",
            "Cyber Defender",
            "Password Pro",
            "Encryption Expert",
            "Hack Proof"
        };

        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, badges.size() - 1);

        return badges[dis(gen)];
    }
};

int main() {
    std::string password;
    std::cout << "Enter a password to test: ";
    std::getline(std::cin, password);

    auto result = PasswordStrengthChecker::checkPasswordStrength(password);
    std::cout << "Password Strength: " << result.strength << std::endl;
    std::cout << "Entropy: " << result.entropy << " bits" << std::endl;
    std::cout << "Rating Badge: " << result.ratingBadge << std::endl;

    std::cout << "Detailed Metrics:" << std::endl;
    for (const auto &[key, value] : result.detailedMetrics) {
        std::cout << key << ": " << value << std::endl;
    }

    if (!result.feedback.empty()) {
        std::cout << "Suggestions:" << std::endl;
        for (const auto &suggestion : result.feedback) {
            std::cout << "- " << suggestion << std::endl;
        }
    }

    return 0;
}
