# Intrusion-Detection-System

TR:

Bu Python kodu, bir Saldırı Tespit Sistemi oluşturmak için tasarlanmıştır. Tkinter kütüphanesi kullanılarak bir grafik kullanıcı arayüzü (GUI) oluşturulur ve kullanıcıya bir IP adresi, port aralığı ve tarama süresi girme olanağı sağlanır. Kullanıcı bu bilgileri girdikten sonra, sistem belirtilen IP adresine yönelik port taraması yapar. Port taraması sırasında, sistem belirli bir tarama türüne göre (TCP, UDP, SYN veya ICMP) tarama işlemini gerçekleştirir ve açık olan portları tespit eder. Tarama işlemi sırasında ilerleme çubuğu kullanıcıya taramanın ilerleme durumunu gösterir. Sonuçlar günlük alanına yazılır ve güvenlik durumu etiketi üzerindeki metin, tespit edilen açık portlara göre güncellenir. Açık portlar bulunursa, güvenlik durumu etiketi "ATTACK DETECTED" (SALDIRI TESPİT EDİLDİ) olarak değiştirilir; bulunmazsa "No attack detected" (SALDIRI TESPİT EDİLMEDİ) olarak kalır.

EN:

This Python code is designed to create an Intrusion Detection System. It utilizes the Tkinter library to build a graphical user interface (GUI), allowing the user to input an IP address, port range, and scanning time. After entering this information, the system performs a port scan on the specified IP address. During the port scanning process, the system conducts the scan based on a specified scan type (TCP, UDP, SYN, or ICMP) and detects open ports. The progress bar indicates the progress of the scan to the user. The results are logged in the log area, and the text on the security status label is updated based on the detected open ports. If open ports are found, the security status label is changed to "ATTACK DETECTED"; otherwise, it remains as "No attack detected".
