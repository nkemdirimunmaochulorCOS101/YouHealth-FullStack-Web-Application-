/*
  Warnings:

  - Changed the type of `dosage` on the `Medication` table. No cast exists, the column would be dropped and recreated, which cannot be done if there is data, since the column is required.
  - Changed the type of `frequency` on the `Medication` table. No cast exists, the column would be dropped and recreated, which cannot be done if there is data, since the column is required.

*/
-- AlterTable
ALTER TABLE "public"."Medication" DROP COLUMN "dosage",
ADD COLUMN     "dosage" INTEGER NOT NULL,
DROP COLUMN "frequency",
ADD COLUMN     "frequency" INTEGER NOT NULL;
