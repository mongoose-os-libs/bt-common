/*
 * Copyright (c) 2014-2017 Cesanta Software Limited
 * All rights reserved
 */

#include "esp32_bt.h"
#include "esp32_bt_internal.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "bt.h"
#include "bta_api.h"
#include "esp_bt_defs.h"
#include "esp_gap_ble_api.h"
#include "esp_gattc_api.h"

#include "common/cs_dbg.h"
#include "common/queue.h"

static esp_gatt_if_t s_gattc_if;

static void esp32_bt_gattc_ev(esp_gattc_cb_event_t ev, esp_gatt_if_t gattc_if,
                              esp_ble_gattc_cb_param_t *ep) {
  char buf[BT_UUID_STR_LEN], buf2[BT_UUID_STR_LEN], buf3[BT_UUID_STR_LEN];
  switch (ev) {
    case ESP_GATTC_REG_EVT: {
      const struct gattc_reg_evt_param *p = &ep->reg;
      enum cs_log_level ll = ll_from_status(p->status);
      LOG(ll, ("REG if %d st %d app %d", gattc_if, p->status, p->app_id));
      if (p->status != ESP_GATT_OK) break;
      s_gattc_if = gattc_if;
      break;
    }
    case ESP_GATTC_UNREG_EVT: {
      LOG(LL_DEBUG, ("UNREG"));
      break;
    }
    case ESP_GATTC_OPEN_EVT: {
      const struct gattc_open_evt_param *p = &ep->open;
      enum cs_log_level ll = ll_from_status(p->status);
      LOG(ll, ("OPEN st %d cid %d addr %s mtu %d", p->status, p->conn_id,
               mgos_bt_addr_to_str(p->remote_bda, buf), p->mtu));
      break;
    }
    case ESP_GATTC_READ_CHAR_EVT: {
      const struct gattc_read_char_evt_param *p = &ep->read;
      enum cs_log_level ll = ll_from_status(p->status);
      LOG(ll,
          ("READ st %d cid %d svc %s char %s val_type 0x%x val_len %d",
           p->status, p->conn_id, mgos_bt_uuid_to_str(&p->srvc_id.id.uuid, buf),
           mgos_bt_uuid_to_str(&p->char_id.uuid, buf2), p->value_type,
           p->value_len));
      break;
    }
    case ESP_GATTC_WRITE_CHAR_EVT: {
      const struct gattc_write_evt_param *p = &ep->write;
      enum cs_log_level ll = ll_from_status(p->status);
      LOG(ll, ("WRITE st %d cid %d svc %s char %s", p->status, p->conn_id,
               mgos_bt_uuid_to_str(&p->srvc_id.id.uuid, buf),
               mgos_bt_uuid_to_str(&p->char_id.uuid, buf2)));
      break;
    }
    case ESP_GATTC_CLOSE_EVT: {
      const struct gattc_close_evt_param *p = &ep->close;
      enum cs_log_level ll = ll_from_status(p->status);
      LOG(ll, ("CLOSE st %d cid %d addr %s reason %d", p->status, p->conn_id,
               mgos_bt_addr_to_str(p->remote_bda, buf), p->reason));
      break;
    }
    case ESP_GATTC_SEARCH_CMPL_EVT: {
      const struct gattc_search_cmpl_evt_param *p = &ep->search_cmpl;
      enum cs_log_level ll = ll_from_status(p->status);
      LOG(ll, ("SEARCH_CMPL st %d cid %d", p->status, p->conn_id));
      break;
    }
    case ESP_GATTC_SEARCH_RES_EVT: {
      const struct gattc_search_res_evt_param *p = &ep->search_res;
      LOG(LL_DEBUG,
          ("SEARCH_RES cid %d svc %s %d%s", p->conn_id,
           mgos_bt_uuid_to_str(&p->srvc_id.id.uuid, buf), p->srvc_id.id.inst_id,
           (p->srvc_id.is_primary ? " primary" : "")));
      break;
    }
    case ESP_GATTC_READ_DESCR_EVT: {
      const struct gattc_read_char_evt_param *p = &ep->read;
      enum cs_log_level ll = ll_from_status(p->status);
      LOG(ll,
          ("READ_DESCR st %d cid %d svc %s descr %s val_type 0x%x val_len %d",
           p->status, p->conn_id, mgos_bt_uuid_to_str(&p->srvc_id.id.uuid, buf),
           mgos_bt_uuid_to_str(&p->descr_id.uuid, buf2), p->value_type,
           p->value_len));
      break;
    }
    case ESP_GATTC_WRITE_DESCR_EVT: {
      const struct gattc_write_evt_param *p = &ep->write;
      enum cs_log_level ll = ll_from_status(p->status);
      LOG(ll, ("WRITE_DESCR st %d cid %d svc %s char %s", p->status, p->conn_id,
               mgos_bt_uuid_to_str(&p->srvc_id.id.uuid, buf),
               mgos_bt_uuid_to_str(&p->char_id.uuid, buf2)));
      break;
    }
    case ESP_GATTC_NOTIFY_EVT: {
      const struct gattc_notify_evt_param *p = &ep->notify;
      LOG(LL_DEBUG,
          ("%s cid %d addr %s svc %s char %s val_len %d",
           (p->is_notify ? "NOTIFY" : "INDICATE"), p->conn_id,
           mgos_bt_addr_to_str(p->remote_bda, buf),
           mgos_bt_uuid_to_str(&p->srvc_id.id.uuid, buf2),
           mgos_bt_uuid_to_str(&p->char_id.uuid, buf3), p->value_len));
      break;
    }
    case ESP_GATTC_PREP_WRITE_EVT: {
      LOG(LL_DEBUG, ("PREP_WRITE"));
      break;
    }
    case ESP_GATTC_EXEC_EVT: {
      const struct gattc_exec_cmpl_evt_param *p = &ep->exec_cmpl;
      enum cs_log_level ll = ll_from_status(p->status);
      LOG(ll, ("EXEC st %d cid %d", p->status, p->conn_id));
      break;
    }
    case ESP_GATTC_ACL_EVT: {
      LOG(LL_DEBUG, ("ACL"));
      break;
    }
    case ESP_GATTC_CANCEL_OPEN_EVT: {
      LOG(LL_DEBUG, ("CANCEL_OPEN"));
      break;
    }
    case ESP_GATTC_SRVC_CHG_EVT: {
      const struct gattc_srvc_chg_evt_param *p = &ep->srvc_chg;
      LOG(LL_DEBUG, ("SRVC_CHG %s", mgos_bt_addr_to_str(p->remote_bda, buf)));
      break;
    }
    case ESP_GATTC_ENC_CMPL_CB_EVT: {
      LOG(LL_DEBUG, ("ENC_CMPL"));
      break;
    }
    case ESP_GATTC_CFG_MTU_EVT: {
      const struct gattc_cfg_mtu_evt_param *p = &ep->cfg_mtu;
      enum cs_log_level ll = ll_from_status(p->status);
      LOG(ll, ("CFG_MTU st %d cid %d mtu %d", p->status, p->conn_id, p->mtu));
      break;
    }
    case ESP_GATTC_ADV_DATA_EVT: {
      LOG(LL_DEBUG, ("ADV_DATA"));
      break;
    }
    case ESP_GATTC_MULT_ADV_ENB_EVT: {
      LOG(LL_DEBUG, ("MULT_ADV_ENB"));
      break;
    }
    case ESP_GATTC_MULT_ADV_UPD_EVT: {
      LOG(LL_DEBUG, ("MULT_ADV_UPD"));
      break;
    }
    case ESP_GATTC_MULT_ADV_DATA_EVT: {
      LOG(LL_DEBUG, ("MULT_ADV_DATA"));
      break;
    }
    case ESP_GATTC_MULT_ADV_DIS_EVT: {
      LOG(LL_DEBUG, ("MULT_ADV_DIS"));
      break;
    }
    case ESP_GATTC_CONGEST_EVT: {
      const struct gattc_congest_evt_param *p = &ep->congest;
      LOG(LL_DEBUG,
          ("CONGEST cid %d%s", p->conn_id, (p->congested ? " congested" : "")));
      break;
    }
    case ESP_GATTC_BTH_SCAN_ENB_EVT: {
      LOG(LL_DEBUG, ("BTH_SCAN_ENB"));
      break;
    }
    case ESP_GATTC_BTH_SCAN_CFG_EVT: {
      LOG(LL_DEBUG, ("BTH_SCAN_CFG"));
      break;
    }
    case ESP_GATTC_BTH_SCAN_RD_EVT: {
      LOG(LL_DEBUG, ("BTH_SCAN_RD"));
      break;
    }
    case ESP_GATTC_BTH_SCAN_THR_EVT: {
      LOG(LL_DEBUG, ("BTH_SCAN_THR"));
      break;
    }
    case ESP_GATTC_BTH_SCAN_PARAM_EVT: {
      LOG(LL_DEBUG, ("BTH_SCAN_PARAM"));
      break;
    }
    case ESP_GATTC_BTH_SCAN_DIS_EVT: {
      LOG(LL_DEBUG, ("BTH_SCAN_DIS"));
      break;
    }
    case ESP_GATTC_SCAN_FLT_CFG_EVT: {
      LOG(LL_DEBUG, ("SCAN_FLT_CFG"));
      break;
    }
    case ESP_GATTC_SCAN_FLT_PARAM_EVT: {
      LOG(LL_DEBUG, ("SCAN_FLT_PARAM"));
      break;
    }
    case ESP_GATTC_SCAN_FLT_STATUS_EVT: {
      LOG(LL_DEBUG, ("SCAN_FLT_STATUS"));
      break;
    }
    case ESP_GATTC_ADV_VSC_EVT: {
      LOG(LL_DEBUG, ("SCAN_ADV_VSC"));
      break;
    }
    case ESP_GATTC_GET_CHAR_EVT: {
      const struct gattc_get_char_evt_param *p = &ep->get_char;
      enum cs_log_level ll = ll_from_status(p->status);
      LOG(ll, ("GET_CHAR st %d cid %d svc %s char %s prop %02x", p->status,
               p->conn_id, mgos_bt_uuid_to_str(&p->srvc_id.id.uuid, buf),
               mgos_bt_uuid_to_str(&p->char_id.uuid, buf2), p->char_prop));
      break;
    }
    case ESP_GATTC_GET_DESCR_EVT: {
      const struct gattc_get_descr_evt_param *p = &ep->get_descr;
      enum cs_log_level ll = ll_from_status(p->status);
      LOG(ll, ("GET_DESCR st %d cid %d svc %s char %s descr %s", p->status,
               p->conn_id, mgos_bt_uuid_to_str(&p->srvc_id.id.uuid, buf),
               mgos_bt_uuid_to_str(&p->char_id.uuid, buf2),
               mgos_bt_uuid_to_str(&p->descr_id.uuid, buf3)));
      break;
    }
    case ESP_GATTC_GET_INCL_SRVC_EVT: {
      const struct gattc_get_incl_srvc_evt_param *p = &ep->get_incl_srvc;
      enum cs_log_level ll = ll_from_status(p->status);
      LOG(ll, ("GET_INCL_SRVC st %d cid %d svc %s incl_svc %s", p->status,
               p->conn_id, mgos_bt_uuid_to_str(&p->srvc_id.id.uuid, buf),
               mgos_bt_uuid_to_str(&p->incl_srvc_id.id.uuid, buf)));
      break;
    }
    case ESP_GATTC_REG_FOR_NOTIFY_EVT: {
      const struct gattc_reg_for_notify_evt_param *p = &ep->reg_for_notify;
      enum cs_log_level ll = ll_from_status(p->status);
      LOG(ll, ("REG_FOR_NOTIFY st %d svc %s char %s", p->status,
               mgos_bt_uuid_to_str(&p->srvc_id.id.uuid, buf),
               mgos_bt_uuid_to_str(&p->char_id.uuid, buf2)));
      break;
    }
    case ESP_GATTC_UNREG_FOR_NOTIFY_EVT: {
      const struct gattc_unreg_for_notify_evt_param *p = &ep->unreg_for_notify;
      enum cs_log_level ll = ll_from_status(p->status);
      LOG(ll, ("UNREG_FOR_NOTIFY st %d svc %s char %s", p->status,
               mgos_bt_uuid_to_str(&p->srvc_id.id.uuid, buf),
               mgos_bt_uuid_to_str(&p->char_id.uuid, buf2)));
      break;
    }
    case ESP_GATTC_CONNECT_EVT: {
      const struct gattc_connect_evt_param *p = &ep->connect;
      enum cs_log_level ll = ll_from_status(p->status);
      LOG(ll, ("CONNECT st %d cid %d addr %s", p->status, p->conn_id,
               mgos_bt_addr_to_str(p->remote_bda, buf)));
      break;
    }
    case ESP_GATTC_DISCONNECT_EVT: {
      const struct gattc_disconnect_evt_param *p = &ep->disconnect;
      enum cs_log_level ll = ll_from_status(p->status);
      LOG(ll, ("DISCONNECT st %d cid %d addr %s", p->status, p->conn_id,
               mgos_bt_addr_to_str(p->remote_bda, buf)));
      break;
    }
  }
}

bool esp32_bt_gattc_init(void) {
  return (esp_ble_gattc_register_callback(esp32_bt_gattc_ev) == ESP_OK &&
          esp_ble_gattc_app_register(0) == ESP_OK);
}
