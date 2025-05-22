-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Host: 127.0.0.1
-- Generation Time: May 22, 2025 at 12:22 AM
-- Server version: 10.4.28-MariaDB
-- PHP Version: 8.2.4

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `dataproject`
--

-- --------------------------------------------------------

--
-- Table structure for table `documents`
--

CREATE TABLE `documents` (
  `id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `filename` varchar(255) NOT NULL,
  `encrypted_path` varchar(255) NOT NULL,
  `file_type` varchar(10) NOT NULL,
  `sha256_hash` char(64) NOT NULL,
  `signature_path` varchar(255) DEFAULT NULL,
  `uploaded_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `public_key_path` varchar(255) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `documents`
--

INSERT INTO `documents` (`id`, `user_id`, `filename`, `encrypted_path`, `file_type`, `sha256_hash`, `signature_path`, `uploaded_at`, `public_key_path`) VALUES
(8, 9, 'Data_Integrity_and_Authentication_Final_Project_-_Spring_2024-2025.pdf', 'Mariam Mostafa/Data_Integrity_and_Authentication_Final_Project_-_Spring_2024-2025.pdf/Data_Integrity_and_Authentication_Final_Project_-_Spring_2024-2025.pdf.enc', 'pdf', 'b58451f0acc6a4414b2df6b12b5ca7c980362256879989a950f40eaa9377a5ee', 'Mariam Mostafa/Data_Integrity_and_Authentication_Final_Project_-_Spring_2024-2025.pdf/Data_Integrity_and_Authentication_Final_Project_-_Spring_2024-2025.pdf.sig', '2025-05-21 12:11:28', 'Mariam Mostafa/Data_Integrity_and_Authentication_Final_Project_-_Spring_2024-2025.pdf/Data_Integrity_and_Authentication_Final_Project_-_Spring_2024-2025.pdf.pub'),
(9, 9, 'Test.txt', 'Mariam Mostafa/Test.txt/Test.txt.enc', 'txt', '8944ea42c48361c09327324013421077aa7387f7f42103747c02cc6d8b3095cb', 'Mariam Mostafa/Test.txt/Test.txt.sig', '2025-05-21 14:48:10', 'Mariam Mostafa/Test.txt/Test.txt.pub');

-- --------------------------------------------------------

--
-- Table structure for table `login_logs`
--

CREATE TABLE `login_logs` (
  `id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `ip_address` varchar(45) NOT NULL,
  `login_time` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `login_logs`
--

INSERT INTO `login_logs` (`id`, `user_id`, `ip_address`, `login_time`) VALUES
(1, 1, '127.0.0.1', '2025-04-29 02:24:12'),
(2, 1, '127.0.0.1', '2025-04-29 14:53:24'),
(3, 1, '127.0.0.1', '2025-04-29 15:19:31'),
(4, 1, '127.0.0.1', '2025-04-29 18:51:45'),
(5, 1, '127.0.0.1', '2025-04-29 19:14:17'),
(6, 1, '127.0.0.1', '2025-04-29 19:47:39'),
(7, 1, '127.0.0.1', '2025-05-01 00:16:42'),
(8, 1, '127.0.0.1', '2025-05-01 11:49:45'),
(11, 1, '127.0.0.1', '2025-05-20 22:22:07'),
(12, 1, '127.0.0.1', '2025-05-21 06:18:24'),
(16, 1, '127.0.0.1', '2025-05-21 10:41:34'),
(20, 1, '127.0.0.1', '2025-05-21 14:58:49'),
(21, 9, '127.0.0.1', '2025-05-21 19:23:06'),
(22, 13, '127.0.0.1', '2025-05-21 19:27:49'),
(23, 14, '127.0.0.1', '2025-05-21 19:54:17'),
(24, 13, '127.0.0.1', '2025-05-21 21:15:03'),
(25, 13, '127.0.0.1', '2025-05-21 21:16:47'),
(27, 16, '127.0.0.1', '2025-05-21 21:56:26'),
(28, 13, '127.0.0.1', '2025-05-21 21:59:50');

-- --------------------------------------------------------

--
-- Table structure for table `system_logs`
--

CREATE TABLE `system_logs` (
  `id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `action` varchar(255) NOT NULL,
  `timestamp` datetime DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `system_logs`
--

INSERT INTO `system_logs` (`id`, `user_id`, `action`, `timestamp`) VALUES
(1, 9, 'Uploaded a document', '2025-05-21 17:48:10'),
(2, 14, 'Uploaded a document', '2025-05-21 21:39:57'),
(3, 14, 'Uploaded a document', '2025-05-21 22:07:35'),
(4, 14, 'Deleted document: hannah.txt', '2025-05-21 22:07:43'),
(5, 14, 'Uploaded a document', '2025-05-21 22:10:55'),
(6, 14, 'Deleted document: hannah.txt', '2025-05-21 22:11:05');

-- --------------------------------------------------------

--
-- Table structure for table `users`
--

CREATE TABLE `users` (
  `id` int(11) NOT NULL,
  `username` varchar(255) NOT NULL,
  `email` varchar(255) NOT NULL,
  `password_hash` varchar(255) DEFAULT NULL,
  `github_id` varchar(255) DEFAULT NULL,
  `google_id` varchar(255) DEFAULT NULL,
  `auth_method` enum('manual','github','google') NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `facebook_id` varchar(100) DEFAULT NULL,
  `role` varchar(20) NOT NULL DEFAULT 'user',
  `twofa_secret` varchar(32) DEFAULT NULL,
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  `nickname` varchar(50) DEFAULT NULL,
  `photo` varchar(255) DEFAULT NULL,
  `is_admin` tinyint(1) NOT NULL DEFAULT 0,
  `is_superadmin` tinyint(1) NOT NULL DEFAULT 0,
  `totp_secret` varchar(32) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `users`
--

INSERT INTO `users` (`id`, `username`, `email`, `password_hash`, `github_id`, `google_id`, `auth_method`, `created_at`, `facebook_id`, `role`, `twofa_secret`, `updated_at`, `nickname`, `photo`, `is_admin`, `is_superadmin`, `totp_secret`) VALUES
(1, 'A-Lordoz', 'A-Lordoz@users.noreply.github.com', NULL, '154616731', NULL, 'github', '2025-04-29 00:16:01', NULL, 'user', NULL, '2025-05-21 15:06:09', NULL, NULL, 0, 0, NULL),
(6, 'Ahmed Mahmoud', 'ahmedlordacio@gmail.com', NULL, NULL, NULL, '', '2025-05-01 00:14:19', '4120999901461208', 'user', NULL, '2025-05-21 16:11:51', NULL, NULL, 1, 0, NULL),
(9, 'Mariam Mostafa', 'recoveryahmedlordacio@gmail.com', NULL, NULL, 'None', 'google', '2025-05-01 00:18:05', NULL, 'user', NULL, '2025-05-21 16:39:08', 'Marioma', 'Screenshot_2025-05-21_135508.png', 1, 0, NULL),
(13, 'admin', '#@@1admin1@@#@gmail.com', '$2b$12$741ULKv0AL0nXJ0EPTrX9.xKJkLa900irNMUYXhUESS.9.dHGPnP.', NULL, NULL, 'manual', '2025-05-21 14:28:40', NULL, 'user', NULL, '2025-05-21 21:59:50', NULL, NULL, 1, 1, 'PRBDSYCORRNRCWO5JLZ2JGIWCZGLPG2L'),
(14, 'Hannah Emad', 'hannahemad@gmail.com', '$2b$12$/M/XLdn22Mr9youV6I0vOeUDtsdxWGudSjvcsL8DApKlhHPeajfG6', NULL, NULL, 'manual', '2025-05-21 18:38:14', NULL, 'user', NULL, '2025-05-21 19:53:56', NULL, NULL, 0, 0, NULL),
(16, 'Test', 'test@gmail.com', '$2b$12$dC0WgSE/Sd50O2kfCkhsXe/Tt51Fc6hgkGVH/rKXNuHm/4SeiJJr.', NULL, NULL, 'manual', '2025-05-21 21:53:33', NULL, 'user', NULL, '2025-05-21 21:53:33', NULL, NULL, 0, 0, 'OCXSSDXUROFKDUCXQ7NSAAC7MVQ7EP5X');

--
-- Indexes for dumped tables
--

--
-- Indexes for table `documents`
--
ALTER TABLE `documents`
  ADD PRIMARY KEY (`id`),
  ADD KEY `user_id` (`user_id`);

--
-- Indexes for table `login_logs`
--
ALTER TABLE `login_logs`
  ADD PRIMARY KEY (`id`),
  ADD KEY `user_id` (`user_id`);

--
-- Indexes for table `system_logs`
--
ALTER TABLE `system_logs`
  ADD PRIMARY KEY (`id`),
  ADD KEY `user_id` (`user_id`);

--
-- Indexes for table `users`
--
ALTER TABLE `users`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `username` (`username`),
  ADD UNIQUE KEY `email` (`email`),
  ADD UNIQUE KEY `github_id` (`github_id`),
  ADD UNIQUE KEY `google_id` (`google_id`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `documents`
--
ALTER TABLE `documents`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=13;

--
-- AUTO_INCREMENT for table `login_logs`
--
ALTER TABLE `login_logs`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=29;

--
-- AUTO_INCREMENT for table `system_logs`
--
ALTER TABLE `system_logs`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=7;

--
-- AUTO_INCREMENT for table `users`
--
ALTER TABLE `users`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=17;

--
-- Constraints for dumped tables
--

--
-- Constraints for table `documents`
--
ALTER TABLE `documents`
  ADD CONSTRAINT `documents_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `login_logs`
--
ALTER TABLE `login_logs`
  ADD CONSTRAINT `login_logs_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `system_logs`
--
ALTER TABLE `system_logs`
  ADD CONSTRAINT `system_logs_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
