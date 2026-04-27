#this file calculates the entropy per chunk 
import math
import os
from typing import Dict, List


CHUNK_SIZE = 1024 #fixed chunk size in bytes as per architecture


class LumenEngine:
    #core_analysis_engine — splits a binary file into 1024-byte segments
    #and computes shannon entropy for each one.

    def __init__(self, file_path: str):
        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"target file not found: {file_path}")
        self.file_path = file_path

    def _compute_entropy(self, chunk: bytes) -> float:
        #computes_H = -sum(p_i * log2(p_i)) for all byte values 0-255 in the chunk.
        if not chunk:
            return 0.0
        total_bytes = len(chunk)
        freq = [0] * 256
        for byte in chunk: freq[byte] += 1
        entropy = 0.0
        for count in freq:
            if count == 0: continue
            p_i = count / total_bytes
            entropy -= p_i * math.log2(p_i)
        return entropy

    def _compute_chi_square(self, chunk: bytes) -> float:
        #computes_the chi-square statistic against a uniform distribution.
        #X2 = sum((observed - expected)^2 / expected)
        if not chunk:
            return 0.0
        
        total_bytes = len(chunk)
        expected = total_bytes / 256.0 #uniform distribution assumption
        
        freq = [0] * 256
        for byte in chunk:
            freq[byte] += 1
            
        chi_square = 0.0
        for count in freq:
            chi_square += ((count - expected) ** 2) / expected
            
        return chi_square

    def analyze(self) -> List[Dict]:
        #reads_the file in binary mode, chunks it, and returns analysis results.
        #each_dict has: segment_index (int), entropy_score (float), chi_square (float), raw_bytes (bytes)
        results = []

        with open(self.file_path, "rb") as f:
            segment_index = 0
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break #eof

                entropy_score = self._compute_entropy(chunk)
                chi_score     = self._compute_chi_square(chunk)

                results.append({
                    "segment_index": segment_index,
                    "entropy_score": round(entropy_score, 6),
                    "chi_square_score": round(chi_score, 4),
                    "raw_bytes": chunk,
                })

                segment_index += 1

        return results


if __name__ == "__main__":
    import tempfile

    #create_a temporary dummy text file to run through the engine
    dummy_content = (
        "LumenAid steganography detection test.\n"
        "This file contains repetitive ascii text which should produce low entropy.\n"
    ) * 20 #repeat to get a decent sized file

    #write_the dummy file to a temp location
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tmp:
        tmp.write(dummy_content)
        tmp_path = tmp.name

    print(f"[lumenaid] test file created at: {tmp_path}")
    print(f"[lumenaid] file size: {os.path.getsize(tmp_path)} bytes\n")

    engine = LumenEngine(tmp_path)
    segments = engine.analyze()

    print(f"[lumenaid] total segments produced: {len(segments)}\n")
    print(f"{'Segment':<10} {'Entropy Score':<18} {'Chunk Size (bytes)'}")
    print("-" * 45)

    for seg in segments:
        print(
            f"{seg['segment_index']:<10} "
            f"{seg['entropy_score']:<18} "
            f"{len(seg['raw_bytes'])}"
        )

    #cleanup_temp file
    os.remove(tmp_path)
    print("\n[lumenaid] temp file cleaned up. engine test complete.")
