#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

#include "rfal_nfc.h"
#include "st25r3916.h"
#include "pltf_gpio.h"

#include "poom_nfc_reader.h"
#include "poom_nfc_core.h"

/* Shared semaphore used by platform timer/gpio glue (pltf_*). */
SemaphoreHandle_t rfal_sem = NULL;

#define ST25R3916_I2C_ADDR (0xA0U >> 1)

TaskHandle_t irq_task_h = NULL;
static bool s_inited = false;

/**
 * @brief Runs the internal task for this module.
 *
 * @param[in] arg Parameter passed to the function.
 * @return void
 */
static void irq_task(void *arg)
{
    (void)arg;
    while (1)
    {
        ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
        if ((irq_task_h != NULL) && s_inited)
        {
            platformIsr();
        }
    }
}

bool poom_nfc_core_init(void)
{
    if (s_inited)
    {
        return true;
    }

    if (rfal_sem == NULL)
    {
        rfal_sem = xSemaphoreCreateBinary();
        if (rfal_sem == NULL)
        {
            printf("poom_nfc_core: failed to create rfal_sem\r\n");
            return false;
        }
    }

    i2c_register_device(ST25R3916_I2C_ADDR);

    if (irq_task_h == NULL)
    {
        BaseType_t ok = xTaskCreate(irq_task, "st25_irq", 4096, NULL, 20, &irq_task_h);
        if (ok != pdPASS)
        {
            printf("poom_nfc_core: failed to create irq_task\r\n");
            return false;
        }
    }

    if (!poom_nfc_reader_init())
    {
        printf("poom_nfc_core: poom_nfc_reader_init() failed\r\n");
        return false;
    }

    s_inited = true;
    printf("  NFC: initialized\r\n");
    return true;
}

bool poom_nfc_core_read_once(uint32_t timeout_ms)
{
    if (!s_inited && !poom_nfc_core_init())
    {
        return false;
    }

    rfalNfcDevice *dev = NULL;
    bool ok = false;

    if (poom_nfc_reader_scan_once(&dev, timeout_ms))
    {
        ok = poom_nfc_reader_active(dev);
    }

    rfalNfcDeactivate(RFAL_NFC_DEACTIVATE_IDLE);
    rfalFieldOff();

    return ok;
}

void poom_nfc_core_deinit(void)
{
    TaskHandle_t current_task = xTaskGetCurrentTaskHandle();

    rfalNfcDeactivate(RFAL_NFC_DEACTIVATE_IDLE);
    rfalFieldOff();

    s_inited = false;

    if (irq_task_h != NULL)
    {
        if (irq_task_h != current_task)
        {
            TaskHandle_t task = irq_task_h;
            irq_task_h = NULL;
            vTaskDelete(task);
        }
        else
        {
            irq_task_h = NULL;
        }
    }

    (void)rfalDeinitialize();

    if (rfal_sem != NULL)
    {
        vSemaphoreDelete(rfal_sem);
        rfal_sem = NULL;
    }
}
