USE iam_security;
GO
ALTER TABLE anomaly_flags ADD response_note NVARCHAR(500) NULL;
GO
SELECT TOP 0 * FROM anomaly_flags;
GO