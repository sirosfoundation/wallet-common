import { afterEach, assert, beforeEach, describe, it } from "vitest";
import { formatDate } from "./formatDate";

describe("The Date/Time parser", () => {

	it("can match ISO 8601 format without decimals", () => {

		const rawDate = '2026-02-01T07:28:49Z';

		const formattedDate = formatDate(rawDate);

		console.log(rawDate);
		console.log(formattedDate);

		assert(formattedDate != rawDate);

	});

	it("can match ISO 8601 format with two ms decimals", () => {

		const rawDate = '2026-02-01T07:28:49.11Z';

		const formattedDate = formatDate(rawDate);

		console.log(rawDate);
		console.log(formattedDate);

		assert(formattedDate != rawDate);

	});

	it("can match ISO 8601 format with three ms decimals", async () => {
		const rawDate = '2026-02-01T07:28:49.117Z';

		const formattedDate = formatDate(rawDate);

		console.log(rawDate);
		console.log(formattedDate);

		assert(formattedDate != rawDate);
	});

	it("can match simple date YYYY-MM-DD format", async () => {
		const rawDate = '2026-02-01';

		const formattedDate = formatDate(rawDate);

		console.log(rawDate);
		console.log(formattedDate);

		assert(formattedDate != rawDate);
	});

	it("can handle a long format date", async () => {
		const rawDate = 'Sun Feb 01 2026 14:46:19 GMT+0200';

		const formattedDate = formatDate(rawDate);

		console.log(rawDate);
		console.log(formattedDate);

		assert(formattedDate != rawDate);
	});

	it("can match a UNIX timestamp in seconds", async () => {
		const rawDate = 1769896800;

		const formattedDate = formatDate(rawDate);

		console.log(rawDate);
		console.log(formattedDate);

		assert(formattedDate != rawDate);
	});

	it("can match a UNIX timestamp in milliseconds", async () => {
		const rawDate = 1769896800000;

		const formattedDate = formatDate(rawDate);

		console.log(rawDate);
		console.log(formattedDate);

		assert(formattedDate != rawDate);
	});

	it("can match ISO 8601 format with three ms decimals", async () => {
		const rawDate = '2026-10-08T07:28:49.117Z';

		const formattedDate = formatDate(rawDate);

		console.log(rawDate);
		console.log(formattedDate);

		assert(formattedDate != rawDate);
	});

	it("can match ISO 8601 format with six ms decimals", async () => {
		const rawDate = '2026-10-08T07:28:49.117456Z';

		const formattedDate = formatDate(rawDate);

		console.log(rawDate);
		console.log(formattedDate);

		assert(formattedDate != rawDate);
	});

	it("can match ISO 8601 format with nine ms decimals", async () => {
		const rawDate = '2026-10-08T07:28:49.117456789Z';

		const formattedDate = formatDate(rawDate);

		console.log(rawDate);
		console.log(formattedDate);

		assert(formattedDate != rawDate);
	});

	it("cannot match invalid, ISO 8601-like format with ten ms decimals", async () => {
		const rawDate = '2026-10-08T07:28:49.1174567890Z';

		const formattedDate = formatDate(rawDate);

		console.log(rawDate);
		console.log(formattedDate);

		assert(formattedDate == rawDate);
	});

	it("can match a Date object", async () => {
		const rawDate = new Date();

		const formattedDate = formatDate(rawDate);

		console.log(rawDate);
		console.log(formattedDate);

		assert(formattedDate != rawDate);
	});

	describe("in a timezone west of UTC", () => {
		const originalTZ = process.env.TZ;
		beforeEach(() => { process.env.TZ = 'America/Puerto_Rico'; }); // UTC-4
		afterEach(() => { process.env.TZ = originalTZ; });

		it("keeps a YYYY-MM-DD date on its own day", () => {
			assert.equal(formatDate('1987-02-18', 'date'), '18/02/1987');
			assert.equal(formatDate('1987-02-18'), '18/02/1987, 00:00:00');
		});

		it("keeps an mdoc full-date (a Date at midnight UTC) on its own day", () => {
			assert.equal(formatDate(new Date('1987-02-18T00:00:00Z'), 'date'), '18/02/1987');
		});

		it("still shows a point in time in the local timezone", () => {
			assert.equal(formatDate(new Date('1987-02-18T02:00:00Z'), 'date'), '17/02/1987');
			assert.equal(formatDate('2026-02-01T02:00:00Z', 'date'), '31/01/2026');
		});
	});

});
