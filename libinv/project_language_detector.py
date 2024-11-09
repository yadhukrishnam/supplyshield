import os
from collections import Counter

from pygments.lexers import guess_lexer_for_filename


class Project_language_detector:
    def __init__(self, project_directory):
        self.project_directory = project_directory

    def detect_languages(self):
        total_files = 0
        language_counter = Counter()

        for root, _, files in os.walk(self.project_directory):
            for file in files:
                try:
                    lexer = guess_lexer_for_filename(file, "")
                    language = lexer.name
                    language_counter[language] += 1
                    total_files += 1
                except Exception:
                    # Handle exceptions (e.g., unsupported file types)
                    pass

        self.language_percentages = {
            language: count / total_files * 100 for language, count in language_counter.items()
        }

        return self.language_percentages

    def most_used_language(self):
        language_percentages = self.detect_languages()
        most_used_language, _ = max(language_percentages.items(), key=lambda x: x[1])
        return most_used_language
