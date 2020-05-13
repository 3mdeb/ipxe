
FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );


#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ipxe/segment.h>
#include <landing_zone.h>

struct sl_header {
	u16 lz_offet;
	u16 lz_length;
} __attribute__ (( packed ));

struct lz_header {
	u8  uuid[16];
	u32 boot_protocol;
	u32 proto_struct;
	u8  msb_key_hash[20];
} __attribute__ (( packed ));

const unsigned char
lz_header_uuid[16] = { 0x78, 0xf1, 0x26, 0x8e, 0x04, 0x92, 0x11, 0xe9,
                       0x83, 0x2a, 0xc8, 0x5b, 0x76, 0xc4, 0xcc, 0x02 };

static physaddr_t target;

/**
 * Update LZ header
 *
 * @v image		LZ file
 * @v zeropage	Address of zero page
 */
int lz_set ( struct image *image, userptr_t zeropage, userptr_t tgt, int proto ) {
	target = user_to_phys ( tgt, 0 );
	int rc;

	DBGC ( image, "LZ %p is being copied to 0x%lx (0x%lx user)\n",
	       image, target, tgt );

	if ( ( rc = prep_segment ( tgt, image->len, SLB_SIZE ) ) != 0 ) {
		DBGC ( image, "LZ %p could not prepare segment: %s\n",
		       image, strerror ( rc ) );
		return rc;
	}

	memcpy_user ( tgt, 0, image->data, 0, image->len );

	struct sl_header *sl_hdr = ( struct sl_header *) tgt;
	struct lz_header *hdr = ( struct lz_header *) ( tgt + sl_hdr->lz_length );

	DBGC ( image, "LZ %p writing zeropage address: 0x%lx\n", image,
	       user_to_phys ( zeropage, 0 ) );

	hdr->boot_protocol = proto;
	hdr->proto_struct = user_to_phys ( zeropage, 0 );
	return 0;
}

/**
 * Execute Landing Zone image
 *
 * @v image		LZ image
 * @ret rc		Return status code
 */
static int lz_exec ( struct image *image ) {
	if ( ! target ) {
		DBGC ( image, "LZ %p: no target address (unsupported kernel type?)\n",
		       image );
		return -ENOSYS;
	};

	/* TODO: remove hardcoded values */
	/* Set APs in wait-for-SIPI state */
	*((volatile uint32_t *)phys_to_user( 0xfee00300ULL )) = 0x000c0500;

	/* Relinquish all TPM localities */
	*((volatile uint8_t *)phys_to_user(0xFED40000ULL)) = 0x20;
	*((volatile uint8_t *)phys_to_user(0xFED41000ULL)) = 0x20;
	*((volatile uint8_t *)phys_to_user(0xFED42000ULL)) = 0x20;
	*((volatile uint8_t *)phys_to_user(0xFED43000ULL)) = 0x20;
	*((volatile uint8_t *)phys_to_user(0xFED44000ULL)) = 0x20;

	DBGC ( image, "LZ %p performing SKINIT with eax=0x%lx now\n.\n.\n.", image,
	       target );

	__asm__ __volatile__ ( "skinit"
			       : : "a" ( target ) : "memory" );

	/* There is no way for the image to return, since we provide
	 * no return address.
	 */
	assert ( 0 );

	return -ECANCELED; /* -EIMPOSSIBLE */
}

/**
 * Probe Landing Zone image
 *
 * @v image		LZ file
 * @ret rc		Return status code
 */
static int lz_probe ( struct image *image ) {
	int rc;
	struct sl_header sl_hdr;
	struct lz_header hdr;

	if ( image->len > SLB_SIZE ) {
		DBGC ( image, "LZ %p too big for Landing Zone\n",
		       image );
		return -ENOEXEC;
	}
	copy_from_user ( &sl_hdr, image->data, 0, sizeof ( sl_hdr ) );
	copy_from_user ( &hdr, image->data, sl_hdr.lz_length, sizeof ( hdr ) );

	rc = memcmp ( hdr.uuid, lz_header_uuid, sizeof ( lz_header_uuid ) );

	if ( rc == 0 ) {
		image_set_name ( image, "landing_zone" );
		return rc;
	}

	return -ENOEXEC;
}

/** Landing Zone image type */
struct image_type lz_image_type __image_type ( PROBE_NORMAL ) = {
	.name = "landing_zone",
	.probe = lz_probe,
	.exec = lz_exec,
};
